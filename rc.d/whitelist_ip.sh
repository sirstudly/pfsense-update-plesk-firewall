#!/bin/sh

# REQUIRE: FILESYSTEMS
# REQUIRE: NETWORKING
# PROVIDE: whitelist_ip

. /etc/rc.subr

name="whitelist_ip"
rcvar="whitelist_ip_enable"
start_cmd="whitelist_ip_start"
stop_cmd="whitelist_ip_stop"

pidfile="/var/run/${name}.pid"
workdir="/usr/local/whitelist-ip"
command="/usr/local/bin/python3.11 ${workdir}/main.py"

load_rc_config ${name}

whitelist_ip_start() {
  if checkyesno ${rcvar}; then
    echo "Starting Whitelist IP script."

    # Check if the process is already running
    if [ -f "${pidfile}" ] && kill -0 "$(cat ${pidfile})" 2>/dev/null; then
      echo "${name} is already running as PID $(cat ${pidfile})."
      return 1
    fi

    # Start the process in the background and save its PID
    cd "${workdir}"
    ${command} &
    echo $! > ${pidfile}

    # Validate that the PID file was written and process is running
    if ! kill -0 "$(cat ${pidfile})" 2>/dev/null; then
      echo "Failed to start ${name}."
      rm -f ${pidfile}
      return 1
    fi

    echo "${name} started with PID $(cat ${pidfile})."
  fi
}

whitelist_ip_stop() {
  if [ -f "${pidfile}" ]; then
    pid=$(cat ${pidfile})

    echo "Stopping Whitelist IP (PID ${pid})..."

    # Gracefully stop the process
    kill "${pid}" && wait "${pid}" 2>/dev/null

    # Remove the PID file
    rm -f "${pidfile}"

    echo "${name} stopped."
  else
    echo "No PID file found. ${name} may not be running."
  fi
}

run_rc_command "$1"