#!/bin/bash

# srsRAN Synchronized Monitor Script - Simplified Version
# Monitors and manages srsRAN binaries with MiTM fuzzing

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="${SCRIPT_DIR}/container_logs"
FUZZING_LOGS_DIR="${SCRIPT_DIR}/fuzzing_logs"

# Process management
declare -A PIDS
declare -A LOG_FILES
CURRENT_SESSION_ID=""
MITM_PID=""

# Directories
BASE_DIR="/home/asset/ns3"
RIC_DIR="$BASE_DIR/flexric/build/examples/ric"
GNB_DIR="$BASE_DIR/ns-O-RAN-flexric/ns-3-mmwave-oran/"
XAPP_DIR="$BASE_DIR/flexric/build/examples/xApp/c/kpm_rc/"
# Fixed error patterns - removed false positives

ERROR_PATTERNS=(
    "Assertion failed"
    "Segmentation fault"
    "core dumped"
    "FATAL"
    "CRITICAL"
    "Connection refused"
    "Failed to connect"
    "Timeout"
    "Error:"
    "ERROR:"
    "[ERROR]"
    ".cc"
)

mkdir -p "$LOGS_DIR" "$FUZZING_LOGS_DIR"

# Simple logging
log() {
    local level=$1
    local message=$2
    local color=$3
    echo -e "${color}[$(date '+%H:%M:%S')] [$level] $message${NC}"
}

log_info() { log "INFO" "$1" "$CYAN"; }
log_success() { log "SUCCESS" "$1" "$GREEN"; }
log_error() { log "ERROR" "$1" "$RED"; }
log_warning() { log "WARNING" "$1" "$YELLOW"; }

# Cleanup
cleanup() {
    log_warning "Cleaning up..."
    
    # Stop all tracked processes
    for process in "${!PIDS[@]}"; do
        local pid=${PIDS[$process]}
        [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null
    done
    
    # Wait a moment for graceful shutdown
    sleep 2
    
    # Force kill any remaining
    for process in "${!PIDS[@]}"; do
        local pid=${PIDS[$process]}
        [[ -n "$pid" ]] && kill -KILL "$pid" 2>/dev/null
    done
    
    # Cleanup any lingering processes
    pkill -f "nearRT-RIC" 2>/dev/null
    pkill -f "gnb" 2>/dev/null
    pkill -f "xapp_oran_moni" 2>/dev/null
    pkill -f "client_server_ns3.py" 2>/dev/null
    
    exit 0
}

trap cleanup SIGINT SIGTERM

is_running() {
    local pid=$1
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

start_mitm() {
    log_info "Starting MiTM session..."
    pkill -f "client_server_ns3.py" 2>/dev/null
    CURRENT_SESSION_ID=$(date '+%Y%m%d_%H%M%S')
    local mitm_log="$FUZZING_LOGS_DIR/mitm_${CURRENT_SESSION_ID}.log"
    
    cd "$(dirname "$0")" || exit 1
    unbuffer python3 client_server_ns3.py > "$mitm_log" 2>&1 &
    MITM_PID=$!
    cd - >/dev/null || exit 1
    
    if is_running "$MITM_PID"; then
        log_success "MiTM started (PID: $MITM_PID)"
        return 0
    else
        log_error "Failed to start MiTM"
        return 1
    fi
}

start_process() {
    local name=$1
    local command=$2
    local work_dir=$3
    local use_sudo=$4
    
    log_info "Starting $name..."
    local log_file="$LOGS_DIR/${name}_${CURRENT_SESSION_ID}.log"
    LOG_FILES[$name]="$log_file"
    
    cd "$work_dir" || return 1
    
    if [[ "$use_sudo" == "true" ]]; then
        sudo unbuffer bash -c "$command" > "$log_file" 2>&1 &
    else
        unbuffer bash -c "$command" > "$log_file" 2>&1 &
    fi
    
    PIDS[$name]=$!
    cd - >/dev/null || exit 1
    
    if is_running "${PIDS[$name]}"; then
        log_success "$name started (PID: ${PIDS[$name]})"
        return 0
    else
        log_error "Failed to start $name"
        return 1
    fi
}

check_errors() {
    local name=$1
    local log_file=${LOG_FILES[$name]}
    [[ ! -f "$log_file" ]] && return 1
    
    local recent_logs=$(tail -50 "$log_file")
    for pattern in "${ERROR_PATTERNS[@]}"; do
        if echo "$recent_logs" | grep -q "$pattern"; then
            log_error "Real error detected in $name: $pattern"
            return 0
        fi
    done
    return 1
}

wait_for_xapp_success() {
    local timeout=15
    local count=0
    local log_file=${LOG_FILES[xapp]}
    
    log_info "Waiting for xApp success message (timeout: ${timeout}s)..."
    
    while [[ $count -lt $timeout ]]; do
        if [[ -f "$log_file" ]] && grep -q "Test xApp run SUCCESSFULLY" "$log_file"; then
            log_success "xApp completed successfully"
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    log_warning "xApp success timeout after ${timeout}s"
    return 1
}

start_all_services() {
    log_info "Starting all services..."
    
    # Start services in order
    start_process "nearRT-RIC" "./nearRT-RIC" "$RIC_DIR" "false"
    sleep 1
    start_process "gnb" "./waf --run scratch/scenario-zero.cc" "$GNB_DIR" "true"
    sleep 1
    start_process "xapp" "./xapp_kpm_rc -c /usr/local/etc/flexric/xapp_kpm_rc_ho.conf" "$XAPP_DIR" "false"
    
    # Wait for xApp to complete or timeout
    if ! wait_for_xapp_success; then
        log_warning "xApp timed out - will restart session"
        return 1
    fi
    return 0
}

stop_all_services() {
    log_info "Stopping all services..."
    for process in xapp srsue gnb nearRT-RIC; do
        local pid=${PIDS[$process]}
        if [[ -n "$pid" ]] && is_running "$pid"; then
            log_info "Stopping $process (PID: $pid)"
            kill -TERM "$pid" 2>/dev/null
        fi
    done
    
    # Wait for processes to terminate gracefully
    local max_wait=5
    local count=0
    while [[ $count -lt $max_wait ]]; do
        local all_stopped=true
        for process in xapp srsue gnb nearRT-RIC; do
            local pid=${PIDS[$process]}
            if [[ -n "$pid" ]] && is_running "$pid"; then
                all_stopped=false
                break
            fi
        done
        
        if [[ "$all_stopped" == "true" ]]; then
            break
        fi
        
        sleep 1
        ((count++))
    done
    
    # Force kill any remaining processes
    for process in xapp srsue gnb nearRT-RIC; do
        local pid=${PIDS[$process]}
        if [[ -n "$pid" ]] && is_running "$pid"; then
            log_warning "Force killing $process (PID: $pid)"
            kill -KILL "$pid" 2>/dev/null
        fi
        PIDS[$process]=""
    done
    
    # Extra cleanup for any lingering processes
    pkill -f "nearRT-RIC" 2>/dev/null
    pkill -f "gnb" 2>/dev/null  
    pkill -f "srsue" 2>/dev/null
    pkill -f "xapp_oran_moni" 2>/dev/null
    
    log_success "All services stopped"
}

restart_session() {
    log_warning "Restarting session..."
    stop_all_services
    CURRENT_SESSION_ID=$(date '+%Y%m%d_%H%M%S')
    start_all_services
    log_success "Session restarted"
}

monitor_loop() {
    local xapp_start_time=""
    
    while true; do
        # Check if any process died
        local need_restart=false
        
        for process in "${!PIDS[@]}"; do
            local pid=${PIDS[$process]}
            if [[ -n "$pid" ]] && ! is_running "$pid"; then
                log_error "$process died unexpectedly"
                need_restart=true
            elif check_errors "$process"; then
                log_warning "$process has real errors"
                need_restart=true
            fi
        done
        
        # Check xApp timeout (if xApp is running and hasn't completed)
        if [[ -n "${PIDS[xapp]}" ]] && is_running "${PIDS[xapp]}"; then
            # Set start time if not set
            if [[ -z "$xapp_start_time" ]]; then
                xapp_start_time=$(date +%s)
            fi
            
            # Check if xApp completed successfully
            local log_file=${LOG_FILES[xapp]}
            if [[ -f "$log_file" ]] && grep -q "Test xApp run SUCCESSFULLY" "$log_file"; then
                log_success "xApp completed successfully - restarting session"
                need_restart=true
                xapp_start_time=""
            else
                # Check timeout
                local current_time=$(date +%s)
                local elapsed=$((current_time - xapp_start_time))
                if [[ $elapsed -ge 15 ]]; then
                    log_warning "xApp timed out after 15 seconds - restarting session"
                    need_restart=true
                    xapp_start_time=""
                fi
            fi
        else
            # xApp not running, reset start time
            xapp_start_time=""
        fi
        
        # Show status
        echo -e "\n${BLUE}Status:${NC}"
        for process in nearRT-RIC gnb srsue xapp; do
            local pid=${PIDS[$process]}
            if [[ -n "$pid" ]] && is_running "$pid"; then
                echo -e "${GREEN}$process: RUNNING${NC} (PID: $pid)"
            else
                echo -e "${RED}$process: STOPPED${NC}"
            fi
        done
        
        if [[ "$need_restart" == "true" ]]; then
            restart_session
            xapp_start_time=""  # Reset for new session
        fi
        
        sleep 5
    done
}

# Main execution
log_info "=== srsRAN Fuzzer Control Script ==="

# Start MiTM once (it stays running)
start_mitm || { log_error "Failed to start MiTM"; exit 1; }

# Start first session
if ! start_all_services; then
    log_warning "Initial session failed/timed out - restarting"
    restart_session
fi

# Monitor loop
monitor_loop