#!/usr/bin/env bash

#
# Script to gather diagnostic information
#
# PostgresPro, M.Zhilin
#
# v0.1 - added hangkill, hang, state
# v0.2 - use /bin/kill instead of shellin
#        supports flags -p and -D
#        warning of hangkill
#        improved search of victim process
# v0.3 - added check presence of gdb
#		 added check of uid (must be root) 
#		 added try to switch to root via sudo
#		 show list of generated files 
# v0.4 - added '-n' option to gdb to avoid .gdbinit
# 
# v0.5 - add sqlstats into state command
# v0.6 - add pg_stat_activity and held LW locks
# v0.7 - Add AltLinux support & full backtrace
# v0.8 - All files in one archive
# v0.9 - add snap & stacks, use different suffixes for each run
# v1.0 - add target directory and amount of jobs, minor fixes, autotest coverage
# v1.1 - fix typo in pgss detection code

# Let's root it if not root and not postgres
if [ $(id -u) != "0" -a $(id -un) != "postgres" ];
then
    if !(type sudo) >/dev/null 2>&1;
    then
        echo ""
        echo "ERROR!"
        echo "       Please execute program under postgres or root account"
        echo "       Usage of program under other account without sudo is not supported"
        echo ""
        exit 1
    fi

    echo "INFO! Program runs only under root account. Switch to root via sudo."
	echo "      To avoid ask password for sudo, you can add to sudoers:"
	echo "      $USER ALL=(ALL) NOPASSWD: `readlink -f $0`"
	exec sudo "$0" "$@"
	exit 1
fi

unamestr=`uname`
GZIP="gzip"

WITHOUT_PERF="yes"

# Normal way
if [ "$unamestr" = "FreeBSD" ]; then
	SYSCPU=`sysctl -n hw.ncpu`
	WITHOUT_PERF="yes"
	PKGMG="pkg install"
elif [ "$unamestr" = "Linux" ]; then
        distname=`awk '/^ID=/' /etc/*-release | awk -F'=' '{ print tolower($2) }'_`
        SYSCPU=`nproc`
        if [ "$distname" = "altlinux" ]; then
                PKGMG="apt-get install"
        else 
                PKGMG="yum install"
        fi
else
        SYSCPU=`nproc`
	PKGMG="yum install"
fi
OUTPUT=diag_`date '+%Y%m%d_%H%M%S'`_$RANDOM
OUTTAR="${OUTPUT}".tar
OUTTGZ="${OUTPUT}".tar.gz
DESTDIR=`pwd`
MARKER="autovacuum\ launcher"

TERM_USER="${USER}"

_masters=()
_listenport=1
_pgdata=""

# search for non privileged user
function set_term_user {
    local _user _user_detect_cmds _cmd

    _user_detect_cmds=("id -un" "whoami" "logname" "echo $SUDO_USER" "echo $USER" "echo $DOAS_USER")

    # search for not empty, not root
    for _cmd in "${_user_detect_cmds[@]}"; do
      _user=$($_cmd)
      if [ "${_user}" != "root" ] && [ "${_user}" != "" ]; then
        TERM_USER="${_user}"
        return
      fi
    done

    # not root is not found, so root is acceptable
    for _cmd in "${_user_detect_cmds[@]}"; do
      _user=$($_cmd)
      if [ "${_user}" != "" ]; then
        TERM_USER="${_user}"
        return
      fi
    done
}

function prevent_oom_pid {
  # -17 is magic, disable oom_killer for pid
  echo -17 > /proc/${1}/oom_adj
}

function protect_from_oom_killer {
  if [ $(id -u) == "0" ];
  then
    # protect ssh
    pgrep -f "sshd" | while read PID; do prevent_oom_pid ${PID}; done
    # protect parent process
    prevent_oom_pid $PPID
    # protect current process
    prevent_oom_pid $$
  fi
}

add_file_to_output() {
  chown ${TERM_USER}:${TERM_USER} ${@}
  tar -uf ${OUTTAR} ${@}
  rm -f ${@}
}

gzip_outtar() {
  gzip ${OUTTAR}
  chown ${TERM_USER}:${TERM_USER} ${OUTTGZ}
}

get_postmaster_by_port () {

	if [ "$unamestr" = "FreeBSD" ]; then
		sockstat -4lq -p ${1} | cut -f3 -w
	elif (type netstat) >/dev/null 2>&1;
    then
        /bin/netstat -4tanlp 2>/dev/null | grep "${1}" | sed -e 's#.* \([0-9]\{1,\}\)\/.*#\1#g'
	elif (type ss) >/dev/null 2>&1;
    then
        if [ "$distname" = "altlinux" ]; then
	        ss -4tanelp | grep "\:${1}[[:space:]].*post\(master\|gres\)" | sed "s#.*,\([0-9]\{1,\}\),.*#\1#" 
	    else
		    ss -4tanelp | grep "\:${1}[[:space:]].*post\(master\|gres\)" | sed "s#.*pid=\([0-9]\{1,\}\),.*#\1#"
	    fi
	fi
}

get_pgdata_by_pid () {
	if [ "$unamestr" = "FreeBSD" ]; then
		procstat -he ${1} | sed -E 's/.*PGDATA=([^ ]+).*/\1/g'
	else
		/bin/readlink -e /proc/${1}/cwd

	fi
}

get_pgport_by_pid () {
	if [ "$unamestr" = "FreeBSD" ]; then
		sockstat | grep "${1}" | grep tcp4 | cut -f6 -w | cut -f2 -d:
	else
	    if (type netstat) >/dev/null 2>&1;
            then
                if [ "$distname" = "altlinux" ]; then
                    /bin/netstat -A inet -tanlp 2>/dev/null  | grep "${1}" | cut -f2 -d: | cut -f1 -d " "
                 else
                    /bin/netstat -4tanlp 2>/dev/null  | grep "${1}" | cut -f2 -d: | cut -f1 -d " "
                 fi
            elif (type ss) >/dev/null 2>&1;
            then
                ss -4tanlp | grep "pid=${1}," | cut -f2 -d: | cut -f1 -d " "
            fi
	fi
}

get_exe_by_pid () {
	if [ "$unamestr" = "FreeBSD" ]; then
		procstat -hb ${1} | cut -f4 -w
	else
		readlink /proc/${_master}/exe
	fi
}

pg_diagdump_gdbstacks ()
{
    local _master
    
    for _master in ${_masters}
    do
        pg_diadgump_gdbstacks_single ${_master}
    done
}

pg_diadgump_gdbstacks_single ()
{
    local _master _bin _fileid
    
    _master=$1
    _bin=$(get_exe_by_pid ${_master})

    echo "Use ${PARALLEL} jobs for stack gathering"
    printf "Gathering stacks (${_master})... "
    if [[ ! -e ${_bin} ]];
    then
        echo "Can't find postgresql binary of " ${_master} ${_bin}
        ps -g postgres -f
    fi

    cat - > tmp.gdb <<EOF
set width 0
set height 0
set verbose off
file ${_bin}
EOF

    for i in `seq 1 ${PARALLEL}`
    do
        cp tmp.gdb tmp$i.gdb
    done
    rm tmp.gdb

    # it's enough to load postgres binary for debug symbols checking
    cat - > tmp_check.gdb <<EOF
set width 0
set height 0
set verbose off
file ${_bin}
p num_held_lwlocks
p held_lwlocks
EOF

    out_check=$(gdb -batch -q  -n --command=tmp_check.gdb 2>&1 >/dev/null < /dev/null | grep Error)
    rm tmp_check.gdb

    if [ "$out_check" != "" ]; then
        prints=""
    else 
        prints=$"p num_held_lwlocks
        p held_lwlocks
        p MemoryContextStatsDetail(TopMemoryContext, 5000)
        eval \"p *((LWLockHandle (*) [%u]) held_lwlocks)\", num_held_lwlocks
        "
    fi

    _fileid=1
    for _backpid in $(pgrep -P ${_master})
    do 
        cat - >> tmp${_fileid}.gdb <<EOF
attach ${_backpid}
info proc
info frame
info registers
thread apply all bt
x/50xw \$sp
x/10i \$rip
${prints}detach
EOF
        _fileid=$((_fileid % PARALLEL))
        _fileid=$((++_fileid))
    done

    for i in `seq 1 ${PARALLEL}`
    do
        echo quit >> tmp$i.gdb
    done
    
    for i in `seq 1 ${PARALLEL}`
    do
        gdb -q -n --command=tmp$i.gdb >> tmp$i.out 2>&1 &
    done
    wait
    
    for i in `seq 1 ${PARALLEL}`
    do
        cat tmp$i.out >> $OUTPUT.stacks_${_master}
        rm tmp$i.out
        rm tmp$i.gdb
    done
    add_file_to_output $OUTPUT.stacks_${_master}
    
    echo "Done!"
}

pg_diagdump_procfs ()
{
    local _master
    
    for _master in ${_masters}
    do
        pg_diadgump_procfs_single ${_master}
    done
}

pg_diadgump_procfs_single ()
{
    local _master _bin _fileid
    
    _master=$1
    _target=$OUTPUT.procfs_${_master}
    _bin=$(get_exe_by_pid ${_master})

    printf "Gathering procfs information (${_master})... "
    if [[ ! -e ${_bin} ]];
    then
        echo "Can't find postgresql binary of " ${_master} ${_bin}
        ps -g postgres -f
    fi
    
    echo ${_master} >> ${_target}
    cat /proc/${_master}/status >> ${_target} 2>&1
    
    for _backpid in $(pgrep -P ${_master})
    do 
        echo ${_backpid} >> ${_target}
        cat /proc/${_backpid}/status >> ${_target} 2>&1
    done
    
    add_file_to_output ${_target}
    
    echo "Done!"
}

pg_diagdump_perf ()
{
    printf "CPU profiling... "
    if [ -z "${WITHOUT_PROFILING}" ]; 
    then
        rm -f perf.data
        perf record -F 99 -a -g --call-graph=dwarf sleep 2 >$OUTPUT.perf 2>&1 
        perf script --header --fields comm,pid,tid,time,event,ip,sym,dso >> $OUTPUT.perf
        rm perf.data
        add_file_to_output $OUTPUT.perf
    fi
    echo "Done!"
}

pg_diagdump_gcore_running ()
{
    local _master _pid
    
    for _master in ${_masters}
    do
        printf "Gathering coredump (${_master},"
        _pid=$(ps --ppid ${_master} -o pid --sort=-%cpu | grep -v ${_master} | head -2 | tail -1 | awk '{$1=$1};1')
        printf "${_pid})... "
        echo 21 > /proc/${_pid}/coredump_filter
        gcore -o ${OUTPUT}_gcore ${_pid}
        add_file_to_output ${OUTPUT}_gcore.${_pid}
        echo "Done!"
    done
}

pg_diagdump_linux_kerncore_running ()
{
    local _master _pid _oldpattern _cp

    _cp=`which cp`
    _oldpattern=`sysctl -n kernel.core_pattern`
    for _master in ${_masters}
    do
        printf "Kill backend (${_master},"
        _pid=$(ps --ppid ${_master} -o pid --sort=-%cpu | grep -v ${_master} | head -2 | tail -1 | awk '{$1=$1};1')
        echo 63 > /proc/${_pid}/coredump_filter
        printf "${_pid})... "

        sysctl -qw kernel.core_pattern="|${_cp} /dev/stdin ${DESTDIR}/${OUTPUT}.coredump_%p"
        /bin/kill -s ABRT ${_pid}
        sleep 1
        sysctl -qw kernel.core_pattern="${_oldpattern}"
        add_file_to_output $OUTPUT.coredump_*
        echo "Done!"
    done
}

pg_diagdump_sqlsnap () 
{
    local _master _port _su

    # Identify way to execute PSQL
    if [ $(id -u) == "0" ]; then
        _su="su -l postgres -c"
    else
        _su="bash -c"
    fi

    for _master in ${_masters}
    do
        _port=$(get_pgport_by_pid ${_master})
        if $(timeout 1 ${_su} "psql -p ${_port} -c 'select 1;'" > /dev/null)
        then
            echo "PostgreSQL is alive!"
            printf "Please wait a bit to gather stats... "
            ${_su} "psql -p ${_port} -c 'select 1 from pg_stat_statements limit 0'" 2>/dev/null 1>&2
            if [ $? == 0 ]; then
                _pgss=$"COPY ( select * from pg_stat_statements
) TO '/tmp/$OUTPUT.pg_snap_statements.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
"
            else 
                _pgss=""
                echo "WARNING! Please install pg_stat_statements"
            fi
             ${_su} "psql -p ${_port}" >/dev/null << EOF
COPY ( select * from pg_stat_user_tables
) TO '/tmp/$OUTPUT.pg_snap_user_tables.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_activity
) TO '/tmp/$OUTPUT.pg_snap_activity.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);     
COPY ( select * from pg_stat_user_indexes
) TO '/tmp/$OUTPUT.pg_snap_user_indexes.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);           
COPY ( select * from pg_prepared_xacts
) TO '/tmp/$OUTPUT.pg_snap_prepared_xacts.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_replication
) TO '/tmp/$OUTPUT.pg_snap_replication.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_replication_slots
) TO '/tmp/$OUTPUT.pg_snap_replication_slots.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_locks
) TO '/tmp/$OUTPUT.pg_snap_locks.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
${_pgss}
EOF
            if [ "${PWD}" != "/tmp" ]; then
                mv /tmp/$OUTPUT.pg_snap_*.csv ./
            fi
            add_file_to_output $OUTPUT.pg_snap_*
            echo "Done!"
        else
            echo "WARNING! No live PostgreSQL found on listen port ${_port}" >&2
        fi
    done
}

pg_diagdump_sqlstat ()
{
    local _master _port _su

    # Identify way to execute PSQL
    if [ $(id -u) == "0" ]; then
        _su="su -l postgres -c"
    else
        _su="bash -c"
    fi
    
    for _master in ${_masters}
    do
        _port=$(get_pgport_by_pid ${_master})
        if $(timeout 1 ${_su} "psql -p ${_port} -c 'select 1;'" > /dev/null)
        then
            echo "PostgreSQL is alive!"
            printf "Please wait 20 seconds to gather stats... \n"
            ${_su} "psql -p ${_port} -c 'select 1 from pg_stat_statements limit 0'" 2>/dev/null 1>&2
            if [ $? == 0 ]; then
                _pgss_init=$"COPY ( select * from pg_stat_replication
) TO '/tmp/$OUTPUT.pg_stat_replication_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
"
                _pgss_rst=$"select pg_stat_statements_reset();
"
                _pgss_fini=$"COPY ( select * from pg_stat_statements
) TO '/tmp/$OUTPUT.pg_stat_statements_delta.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
"
            else 
                _pgss_init=""
                _pgss_rst=""
                _pgss_fini=""
                echo "WARNING! Please install pg_stat_statements"
            fi

            ${_su} "psql -p ${_port} -c 'select 1 from pgpro_stats_statements limit 0'" 2>/dev/null 1>&2
            if [ $? == 0 ]; then
                _pgpro_ss_init=$"COPY ( select * from pg_stat_replication
) TO '/tmp/$OUTPUT.pg_stat_replication_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
"
                _pgpro_ss_rst=$"select pgpro_stats_statements_reset();
"
                _pgpro_ss_fini_1=$"COPY ( select * from pgpro_stats_statements
) TO '/tmp/$OUTPUT.pgpro_stats_statements.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
"
                _pgpro_ss_fini_2=$"COPY ( select * from pgpro_stats_totals
) TO '/tmp/$OUTPUT.pgpro_stats_totals.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
"
                _pgpro_ss_fini_3=$"COPY ( select * from pgpro_stats_inval_status
) TO '/tmp/$OUTPUT.pgpro_stats_inval_status.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
"
                _pgpro_ss_fini_4=$"COPY ( select * from pgpro_stats_metrics
) TO '/tmp/$OUTPUT.pgpro_stats_metrics.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
"
            else
                _pgpro_ss_init=""
                _pgpro_ss_rst=""
                _pgpro_ss_fini_1=""
                _pgpro_ss_fini_2=""
                _pgpro_ss_fini_3=""
                _pgpro_ss_fini_4=""

                echo "NOTICE! You may install pgpro_stats"
            fi

           ${_su} "psql -p ${_port}" >/dev/null << EOF
COPY ( select * from pg_stat_user_tables
) TO '/tmp/$OUTPUT.pg_stat_tab_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_activity
) TO '/tmp/$OUTPUT.pg_stat_act1.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_user_indexes
) TO '/tmp/$OUTPUT.pg_stat_ind_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
${_pgss_init}
${_pgpro_ss_init}
COPY ( select * from pg_prepared_xacts
) TO '/tmp/$OUTPUT.pg_stat_prepared_xacts_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_replication
) TO '/tmp/$OUTPUT.pg_stat_replication_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_replication_slots
) TO '/tmp/$OUTPUT.pg_stat_replication_slots_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
select pg_stat_reset();
${_pgss_rst}
${_pgpro_ss_rst}
select pg_sleep(20);
COPY ( select * from pg_stat_user_tables
) TO '/tmp/$OUTPUT.pg_stat_tab_delta.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_activity
) TO '/tmp/$OUTPUT.pg_stat_act2.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_user_indexes
) TO '/tmp/$OUTPUT.pg_stat_ind_delta.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
${_pgss_fini}
${_pgpro_ss_fini_1}
${_pgpro_ss_fini_2}
${_pgpro_ss_fini_3}
${_pgpro_ss_fini_4}
COPY ( select * from pg_prepared_xacts
) TO '/tmp/$OUTPUT.pg_stat_prepared_xacts_end.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_replication
) TO '/tmp/$OUTPUT.pg_stat_replication_end.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_replication_slots
) TO '/tmp/$OUTPUT.pg_stat_replication_slots_end.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
EOF
            if [ "${PWD}" != "/tmp" ]; then
                mv /tmp/$OUTPUT.*.csv ./
            fi
            add_file_to_output $OUTPUT.*.csv
            echo "Done!"
        else
            echo "WARNING! No live PostgreSQL found on listen port ${_port}" >&2
        fi
    done

}

pg_diagdump_summary ()
{
    gzip_outtar
    echo ""
    echo "Generated file: ${OUTTAR}.gz"
}

show_help () {
    cat - <<EOF
pg_diagdump is a diagnostic tool for PostgreSQL.

Usage:
  pg_diagdump [-d <TARGET_DIR> ] [-j JOBS] [ -p <LISTEN_PORT> | -D <PGDATA> ] <command>

Flags:
    -d TARGET_DIR   path to directory where result files are stored to (default: current directory)
    -j JOBS         amount of GDB process to gather stacks (default: amount of CPU coress)
    -p LISTEN_PORT  listening port for PostgreSQL database
    -D PGDATA       path to PostgreSQL database data directory

Available commands:
    state           gather profiling and stack info
    stacks          gather stack info
    snap            gather database state information
    hang            gather light core dump and profiling+stack info 
    hangkill        gather full core dump, profiling+stack info and terminate DB
EOF
}

ask_confirmation () 
{
    echo ""
    echo "WARNING! This command will terminate processes of PostgreSQL database"
    echo "         Then PostgreSQL will be restarted unless option restart_after_crash is set to false"
    echo ""

    while true; do
        read -p "Do you want to continue? " yn
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) exit;;
            * ) echo "Please answer yes or no.";;
        esac
    done

}

check_running_pg ()
{
    if ! $(pgrep -f "${MARKER}" > /dev/null)
    then
        echo ""
        echo "ERROR!"
        echo "       Can't find any running PostgreSQL instance"
        echo "       Please check if postgres is running"
        echo ""
        show_help
        exit 1
    fi
}

validate_cluster_params ()
{
    local _master
    
    if [ ! -z "${_pgdata}" ];
    then
        # check exists PGDATA 
        if [ ! -d ${_pgdata} ];
        then
            echo "ERROR! Directory ${_pgdata} doesn't exist"
            exit 1
        fi
        # check postgresql.pid
        if [ ! -f ${_pgdata}/postmaster.pid ];
        then 
            echo "ERROR! File ${_pgdata}/postmaster.pid doesn't exist"
            exit 1
        fi
        _masters=$(head -1 ${_pgdata}/postmaster.pid)
    elif [ ${_listenport} -ne 1 ];
    then
        _master=$(get_postmaster_by_port ${_listenport})
        
        if [ -z "${_master}" ];
        then
            echo "ERROR! Can't find postmaster listening port ${_listenport}"
            exit 1
        fi
        
        _masters=(${_master})
    else
        for BGPID in $(pgrep -f "${MARKER}")
        do
            _master=$(cut -f 4 -d' ' /proc/$BGPID/stat)
            _masters+=(${_master})
        done
    fi

    for _master in ${_masters}
    do
        echo "Found PostgreSQL instance: "
        echo " * postmaster's PID ${_master}"
        echo " * PGDATA $(get_pgdata_by_pid ${_master})"
        echo " * PGPORT $(get_pgport_by_pid ${_master})"
    done
    echo ""

    # check port if specified
    return 0
}

check_installed_pkgs ()
{
    local _missing
    
    _missing=()
    if ! (type pigz) >/dev/null 2>&1;
    then
        if ! (type gzip) >/dev/null 2>&1;
        then
            # if missing install better tool
            _missing+=('pigz')
        else
            echo ""
            echo "WARNING! pigz isn't installed, so I use gzip instead."
            echo ""
        fi
    else
        GZIP='pigz'
    fi

    if ! (type gdb) >/dev/null 2>&1;
    then
        _missing+=('gdb')
    fi

    if ! (type perf) >/dev/null 2>&1;
    then
        if [ -z "${WITHOUT_PERF}" -a -z "${WITHOUT_PROFILING}" ];
        then
            if [ "$distname" = "altlinux" ]; then
                _missing+=('linux-tools-<YOUR KERNEL>')
            else
                _missing+=('perf')
            fi
        else
            WITHOUT_PROFILING=yes
        fi
    fi

    if [ ! -z "${WITHOUT_PROFILING}" ]; 
    then
        echo ""
        echo "WARNING! CPU profiling will be skipped due to environment variables"
        echo ""
    fi

    if [ ${#_missing} -ne 0 ];
    then
        echo ""
        echo "ERROR!"
        echo "       Please install prerequisites: ${PKGMG} ${_missing[*]}"
        echo ""
        exit 1
    fi
}

# Parse parameters

while getopts "h?D:d:j:p:v" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    v)  _verbose=1
        ;;
    p)  _listenport=$OPTARG
        if [ "${_pgdata}" != "" ];
        then
            echo "ERROR! Please specify only one flag: either -p or -D" >&2
            exit 1
        fi
        ;;
    D)  _pgdata=$OPTARG
        if [ ${_listenport} -ne 1 ];
        then
            echo "ERROR! Please specify only one flag: either -p or -D" >&2
            exit 1
        fi
        ;;
    d)  _target=$OPTARG
        if [ ! -d "${_target}" ];
        then
            echo "ERROR! Target directory ${_target} doesn't exist" >&2
            exit 1
        else
            cd ${_target}
        fi
        ;;
    j)  _parallel=$OPTARG
        re='^[0-9]+$'
        if ! [[ ${_parallel} =~ $re ]] ; then
            echo "ERROR! Not a number: ${_parallel}" >&2; exit 1 
        fi
        ;;
    esac
done

PARALLEL="${_parallel:-$SYSCPU}"

shift $((OPTIND-1))
_cmd=$1

if [ ${_listenport} -eq 1 -a "${_pgdata}" = "" ];
then
    show_help
    exit 1
fi

set_term_user
check_installed_pkgs
protect_from_oom_killer
validate_cluster_params
{
    case "$_cmd" in
        smoke)
            exit 0
            ;;
        procfs)
            pg_diagdump_procfs
            pg_diagdump_summary
            exit 0
            ;;            
        stacks)
            pg_diagdump_gdbstacks
            pg_diagdump_summary
            exit 0
            ;;
        snap)
            pg_diagdump_sqlsnap
            pg_diagdump_summary
            exit 0
            ;;
        state)
            pg_diagdump_gdbstacks
            pg_diagdump_perf
            pg_diagdump_sqlstat
            pg_diagdump_summary
            exit 0
            ;;
        hang)			
            pg_diagdump_perf
            pg_diagdump_gdbstacks
            pg_diagdump_gcore_running
            pg_diagdump_summary
            exit 0
            ;;
        hangkill)
            ask_confirmation
            pg_diagdump_perf
            pg_diagdump_gdbstacks
            pg_diagdump_linux_kerncore_running
            pg_diagdump_summary
            exit 0
            ;;
		*)
			if [ ! -z ${_cmd} ]; 
			then
				echo "ERROR! Unknown command: $_cmd"
			fi
			show_help
			exit 1
    esac
}
