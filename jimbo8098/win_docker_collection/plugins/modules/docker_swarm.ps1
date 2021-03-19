#!powershell

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        advertise_addr = @{ type = "str" }
        api_version = @{ type = "str" }
        autolock_managers = @{ type = "bool" }
        ca_cert = @{ type = "str" }
        ca_force_rotate = @{ type = "int" }
        client_cert = @{ type = "str" }
        client_key = @{ type = "str" }
        debug = @{ type = "bool" }
        default_addr_pool = @{ type = "list" }
        dispatcher_heartbeat_period = @{ type = "int" }
        docker_host = @{ type = "str" }
        election_tick = @{ type = "int" }
        force = @{ type = "bool" }
        heartbeat_tick = @{ type = "int" }
        join_token = @{ type = "str" }
        keep_old_snapshots = @{ type = "int" }
        labels = @{ type = "dict" }
        listen_addr = @{ type = "str" }
        log_entries_for_slow_followers = @{ type = "int" }
        name = @{ type = "str" }
        node_cert_expiry = @{ type = "int" }
        node_id = @{ type = "str" }
        remote_addrs = @{ type = "list" }
        rotate_manager_token = @{ type = "bool" }
        rotate_worker_token = @{ type = "bool" }
        signing_ca_cert = @{ type = "str" }
        signing_ca_key = @{ type = "str" }
        snapshot_interval = @{ type = "int" }
        ssl_version = @{ type = "str" }
        state = @{ type = "str"; choices = "absent","present","join","remove" }
        subnet_size = @{ type = "int" }
        task_history_retention_limit = @{ type = "int" }
        timeout = @{ type = "int" }
        tls = @{ type = "bool" }
        tls_hostname = @{ type = "str" }
        validate_certs = @{ type = "bool" }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$args = $module.Params

function Initialize-Swarm {
    param(
        [hashtable] $initargs
    )

    $module.Debug($initargs.advertise_addr)

    $argumentsToAdd = [System.Collections.ArrayList]@();
    if($initargs.advertise_addr -ne ""){
        $argumentsToAdd.Add('--advertise-addr "{0}"' -f $initargs.advertise_addr)
    }
    if($initargs.listen_addr -ne "") {
        $argumentsToAdd.Add('--listen-addr "{0}"' -f $initargs.advertise_addr)
    }
    if($initargs.force_new_cluster -ne "") {
        $argumentsToAdd.Add("--force-new-cluster")
    }

    $module.Debug(($argumentsToAdd))
    try {
        Invoke-Expression -Command "docker swarm init $($argumentsToAdd -join " ")" -ErrorVariable swarmInitErr -OutVariable swarmInitResult
        return @{
            status = "success"
        }
    }
    catch{

        if($swarmInitErr)
        {
            switch -Wildcard ($swarmInitErr)
            {
                "*could not find the system's IP address - specify one with --advertise-addr*" {
                    Write-AnsibleException -err $_ -mess "Couldn't find system's IP address automatically. Define advertise_addr."
                }
                "*advertise address must be a non-zero IP address or network interface (with optional port number)*"{
                    Write-AnsibleException -err $_ -mess "advertise_addr must be a non-zero IP address or network interface (with optional port number)"
                }
                "*failed to listen on remote API address: listen tcp 10.0.1.15:2377: bind: The requested address is not valid in its context*"{
                    Write-AnsibleException -err $_ -mess "Failed to listen on remote API address"
                }
            }
        }
        Write-AnsibleException -err $_ -mess "An unhandled error occurred whilst initializing the swarm."
    }
}


function Write-AnsibleException ([string] $err = $NULL, [string] $mess = $NULL){
    $module.Debug(@"
    ${mess}

    STDOUT: ${out}

    STDERR: ${err}
"@)

    $module.FailJson($mess,$err)
}

function Get-State() {
    param()
    $status = @{
        swarm_active = $NULL
    }

    $retSwarmStateOutput = docker info -f '{{json .Swarm.LocalNodeState}}'
    switch($retSwarmStateOutput)
    {
        '"inactive"'
        {
            $status.swarm_active = $false
            break
        }
        '"active"'
        {
            $status.swarm_active = $true
            break
        }
        default 
        {
            $status.swarm_active = "unknown"
        }
    }
    return $status
}

$returnValue = @{
    before = Get-State
}
switch($args.state){
    "present" {
        if((Get-State).swarm_active -eq $false) {
            $initResult = Initialize-Swarm -initargs @{
                advertise_addr = $args.advertise_addr
                listen_addr = $args.listen_addr
                force_new_cluster = $args.force_new_cluster
            }
        }
    }
}
$returnValue.after = Get-State
$module.ExitJson()