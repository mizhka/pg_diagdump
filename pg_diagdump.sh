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
# v0.7 - Add AltLinux support & full backtrace and

# Let's root it
if [ $(id -u) != "0" ];
then
    if !(type sudo) >/dev/null 2>&1;
    then
        echo ""
        echo "ERROR!"
        echo "       Please execute program under root account"
        echo "       Usage of program under non-root account is not yet supported"
        echo ""
        exit 1
    fi

    echo "WARN! Program runs only under root account. Switch to root via sudo."
	echo "      To avoid ask password for sudo, you can add to sudoers:"
	echo "      $USER ALL=(ALL) NOPASSWD: `readlink -f $0`"
	exec sudo "$0" "$@"
	exit 1
fi

unamestr=`uname`
GZIP="gzip"


# Normal way
if [ "$unamestr" = "FreeBSD" ]; then
	PARALLEL=`sysctl -n hw.ncpu`
	WITHOUT_PERF="yes"
	PKGMG="pkg install"
elif [ "$unamestr" = "Linux" ]; then
        distname=`awk '/^ID=/' /etc/*-release | awk -F'=' '{ print tolower($2) }'_`
        PARALLEL=`nproc`
        if [ "$distname" = "altlinux" ]; then
                PKGMG="apt-get install"
        else 
                PKGMG="yum install"
        fi
else
        PARALLEL=`nproc`
	PKGMG="yum install"
fi
OUTPUT=diag_`date '+%Y%m%d_%H%M%S'`
DESTDIR=`pwd`
MARKER="autovacuum\ launcher"

_masters=()
_listenport=1
_pgdata=""

get_postmaster_by_port () {
	if [ "$unamestr" = "FreeBSD" ]; then
		sockstat -4lq -p ${1} | cut -f3 -w
	elif [ "$distname" = "altlinux" ]; then
	        ss -4tanelp | grep "\:${1}[[:space:]].*post\(master\|gres\)" | sed "s#.*,\([0-9]\{1,\}\),.*#\1#" 
	else
		ss -4tanelp | grep "\:${1}[[:space:]].*post\(master\|gres\)" | sed "s#.*pid=\([0-9]\{1,\}\),.*#\1#"
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
                    /bin/netstat -A inet -tanlp | grep "${1}" | cut -f2 -d: | cut -f1 -d " "
                 else
                    /bin/netstat -4tanlp | grep "${1}" | cut -f2 -d: | cut -f1 -d " "
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

pg_diadgump_gdbstacks_single ()
{
    local _master _bin _fileid
    
    _master=$1
    _bin=$(get_exe_by_pid ${_master})

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

    for i in `seq 1 $PARALLEL`
    do
        cp tmp.gdb tmp$i.gdb
    done
    rm tmp.gdb

    # check debuginfo
    cat - > tmp_check.gdb <<EOF
set width 0
set height 0
set verbose off
file ${_bin}
attach ${_master}
p num_held_lwlocks
p held_lwlocks
eval "p *((LWLockHandle (*) [%u]) held_lwlocks)", num_held_lwlocks
detach
EOF

    out_check=$(gdb -batch -q  -n --command=tmp_check.gdb 2>&1 >/dev/null < /dev/null | grep Error)
    
    if [ "$out_check" != "" ]; then
        prints=""
    else 
        prints=$"p num_held_lwlocks
        p held_lwlocks
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

    for i in `seq 1 $PARALLEL`
    do
        echo quit >> tmp$i.gdb
    done
    
    for i in `seq 1 $PARALLEL`
    do
        gdb -q -n --command=tmp$i.gdb >> tmp$i.out 2>&1 &
    done
    wait
    
    for i in `seq 1 $PARALLEL`
    do
        cat tmp$i.out >> $OUTPUT.stacks_${_master}
        rm tmp$i.out
        #rm tmp$i.gdb
    done
    ${GZIP} $OUTPUT.stacks_${_master}
    
    echo "Done!"
}

pg_diagdump_gdbstacks ()
{
    local _master
    
    for _master in ${_masters}
    do
        pg_diadgump_gdbstacks_single ${_master}
    done
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
        ${GZIP} $OUTPUT.perf
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
        ${GZIP} ${OUTPUT}_gcore.${_pid}
        echo "Done!"
    done
}

pg_diagdump_linux_kerncore_running ()
{
    local _master _pid _oldpattern
    
    _oldpattern=`sysctl -n kernel.core_pattern`
    for _master in ${_masters}
    do
        printf "Kill backend (${_master},"
        _pid=$(ps --ppid ${_master} -o pid --sort=-%cpu | grep -v ${_master} | head -2 | tail -1 | awk '{$1=$1};1')
        echo 63 > /proc/${_pid}/coredump_filter
        printf "${_pid})... "
        
        sysctl -qw kernel.core_pattern="|/bin/sh -c \$@ -- eval exec ${GZIP} --fast > $DESTDIR/$OUTPUT.coredump_%p.gz"
        /bin/kill -s ABRT ${_pid}
        sleep 1
        sysctl -qw kernel.core_pattern="${_oldpattern}"
        echo "Done!"
    done
}

pg_diagdump_sqlstat ()
{
    local _master

    for _master in ${_masters}
    do
        if $(timeout 1 su -l postgres -c "psql -p $(get_pgport_by_pid ${_master}) -c 'select 1;'" > /dev/null)
        then
           echo "PostgreSQL is alive!"
           printf "Please wait 20 seconds to gather stats... "
           su -l postgres -c "psql -p $(get_pgport_by_pid ${_master})" >/dev/null << EOF
COPY ( select * from pg_stat_user_tables
) TO '/tmp/$OUTPUT.pg_stat_tab_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_activity
) TO '/tmp/$OUTPUT.pg_stat_act1.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);     
COPY ( select * from pg_stat_user_indexes
) TO '/tmp/$OUTPUT.pg_stat_ind_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);           
COPY ( select * from pg_stat_statements
) TO '/tmp/$OUTPUT.pg_stat_statements_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_prepared_xacts
) TO '/tmp/$OUTPUT.pg_stat_prepared_xacts_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_replication
) TO '/tmp/$OUTPUT.pg_stat_replication_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_replication_slots
) TO '/tmp/$OUTPUT.pg_stat_replication_slots_init.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
select pg_stat_reset();
select pg_stat_statements_reset();
select pg_sleep(20);
COPY ( select * from pg_stat_user_tables
) TO '/tmp/$OUTPUT.pg_stat_tab_delta.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_activity
) TO '/tmp/$OUTPUT.pg_stat_act2.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);           
COPY ( select * from pg_stat_user_indexes
) TO '/tmp/$OUTPUT.pg_stat_ind_delta.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);           
COPY ( select * from pg_stat_statements
) TO '/tmp/$OUTPUT.pg_stat_statements_delta.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_prepared_xacts
) TO '/tmp/$OUTPUT.pg_stat_prepared_xacts_end.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_stat_replication
) TO '/tmp/$OUTPUT.pg_stat_replication_end.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
COPY ( select * from pg_replication_slots
) TO '/tmp/$OUTPUT.pg_stat_replication_slots_end.csv' (format csv, delimiter ';', ENCODING 'UTF8',header TRUE, FORCE_QUOTE *);
EOF
           mv /tmp/$OUTPUT.pg_stat_*.csv ./
           ${GZIP} $OUTPUT.pg_stat_*
           chown $(whoami) $OUTPUT.pg_stat_*
           echo "Done!"
        fi
    done

}

pg_diagdump_summary ()
{
    echo ""
    echo "Generated files:"
    find "${PWD}" -name ${OUTPUT}\* -exec echo "  "{} \;
}

show_help () {
    cat - <<EOF
pg_diagdump is a diagnostic tool for PostgreSQL.

Usage:
  pg_diagdump [ -p <LISTEN_PORT> | -D <PGDATA> ] <command>

Flags:
    -p LISTEN_PORT  listening port for PostgreSQL database
    -D PGDATA       path to PostgreSQL database data directory

Available commands:
    state           gather profiling and stack info
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
            exit 0
        fi
        # check postgresql.pid
        if [ ! -f ${_pgdata}/postmaster.pid ];
        then 
            echo "ERROR! File ${_pgdata}/postmaster.pid doesn't exist"
            exit 0
        fi
        _masters=$(head -1 ${_pgdata}/postmaster.pid)
    elif [ ${_listenport} -ne 1 ];
    then
        _master=$(get_postmaster_by_port ${_listenport})
        
        if [ -z "${_master}" ];
        then
            echo "ERROR! Can't find postmaster listening port ${_listenport}"
            exit 0
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

while getopts "h?p:D:v" opt; do
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
            echo "ERROR! Please specify only one flag: either -p or -D"
            exit 0
        fi
        ;;
    D)  _pgdata=$OPTARG
        if [ ${_listenport} -ne 1 ];
        then
            echo "ERROR! Please specify only one flag: either -p or -D"
            exit 0
        fi
        ;;
    esac
done

shift $((OPTIND-1))
_cmd=$1

if [ ${_listenport} -eq 1 -a "${_pgdata}" = "" ];
then
    show_help
    exit 1
fi

check_installed_pkgs
validate_cluster_params
{
    case "$_cmd" in
        smoke)
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
			exit 0
    esac
}
