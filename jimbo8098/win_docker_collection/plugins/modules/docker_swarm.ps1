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
        client_cert = @{ type = "string" }
        client_key = @{ type = "string" }
        debug = @{ type = "bool" }
        default_addr_pool = @{ type = "array" }
        dispatcher_heartbeat_period = @{ type = "int" }
        docker_host = @{ type = "string" }
        election_tick = @{ type = "int" }
        force = @{ type = "bool" }
        heartbeat_tick = @{ type = "int" }
        join_token = @{ type = "string" }
        keep_old_snapshots = @{ type = "int" }
        labels = @{ type = "array" }
        listen_addr = @{ type = "string" }
        log_entries_for_slow_followers = @{ type = "int" }
        name = @{ type = "string" }
        node_cert_expiry = @{ type = "int" }
        node_id = @{ type = "string" }
        remote_addrs = @{ type = "array" }
        rotate_manager_token = @{ type = "bool" }
        rotate_worker_token = @{ type = "bool" }
        signing_ca_cert = @{ type = "string" }
        signing_ca_key = @{ type = "string" }
        snapshot_interval = @{ type = "int" }
        ssl_version = @{ type = "string" }
        state = @{ type = "string"; choices = "absent","present","join","remove" }
        subnet_size = @{ type = "int" }
        task_history_retention_limit = @{ type = "int" }
        timeout = @{ type = "int" }
        tls = @{ type = "bool" }
        tls_hostname = @{ type = "string" }
        validate_certs = @{ type = "bool" }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)


$module.Result.values = @{}
$module.ExitJson()