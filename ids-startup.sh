#!/bin/bash

# Install Zeek
sudo apt update
sudo apt install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev -y
cd /tmp
git clone --recursive https://github.com/zeek/zeek
cd zeek
./configure --prefix=/nsm/zeek
make
sudo make install
sudo ln -s /nsm/zeek/bin/zeek /usr/local/bin/zeek
sudo ln -s /nsm/zeek/bin/zeek-cut /usr/local/bin/zeek-cut
sudo ln -s /nsm/zeek/bin/zeekctl /usr/local/bin/zeekctl

cat > /usr/local/bin/handle-fw.py <<EOF
#!/usr/bin/python3

import subprocess
import sys

def runcommand(cmd):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output = process.stdout.read()
    return output.decode()

srcIp = sys.argv[2]
srcIpCIDR = srcIp + "/32"

if sys.argv[1] == "block":

    # Check if already blocked in Armor
    if runcommand("gcloud compute security-policies describe zeek-policy | grep \"" + srcIpCIDR + "\"" ) != "":
        print("Already in place!")
        exit(1)

    # Determine priority to use
    priorityList = runcommand("gcloud compute security-policies describe zeek-policy | grep priority | awk '{print $2}'").split("\n")
    priorityList.remove('')
    for i in range(2, 1000):
        if str(i) not in priorityList:
            priority = i
            break

    # Make block in Armor
    runcommand("gcloud compute security-policies rules create " + str(priority) + " --security-policy zeek-policy --src-ip-ranges=" + srcIpCIDR + " --action=\"deny-403\"")

    # Check if already blocked in firewall
    output = runcommand("gcloud compute firewall-rules list --format=\"table(sourceRanges.list():label=SRC_RANGES)\"").split("\n")
    if srcIpCIDR in output:
        print("Firewall rule already in place!")
        exit(1)

    # Make the block in firewall
    runcommand("gcloud compute firewall-rules create 'zeek" + srcIp.replace(".","x") + "' --action=DENY --rules tcp,udp,icmp --priority=1 --source-ranges=" + srcIpCIDR)
    exit(0)

if sys.argv[1] == "release":
    priority = runcommand("gcloud compute security-policies describe zeek-policy | grep -A3 \"" + srcIpCIDR + "\" | grep priority | awk '{print $2}' | head -1")
    runcommand("echo \"Y\" | gcloud compute security-policies rules delete --security-policy zeek-policy " + priority)
    runcommand("echo \"Y\" | gcloud compute firewall-rules delete 'zeek" + srcIp.replace(".","x") + "'")
    exit(0)
EOF

sudo chmod +x /usr/local/bin/handle-fw.py

cat > /nsm/zeek/share/zeek/policy/misc/gcloud-catch-release.zeek <<EOF
@load base/frameworks/netcontrol/plugins/pfblock.zeek
@load policy/frameworks/netcontrol/catch-and-release.zeek
@load base/frameworks/sumstats

redef NetControl::catch_release_intervals=[15 min, 1 hr, 4 hrs, 24 hrs];

event NetControl::init()
    {
    local pfblock_plugin = NetControl::create_pfblock("");
    NetControl::activate(pfblock_plugin, 0);
    }

event http_reply (c: connection, version: string, code: count, reason: string) {
    local blockIp: addr;
    if (code == 401 || code == 403 || code == 404) {
        if (c\$http ?\$ proxied) {
            for (header in c\$http\$proxied) {
                if (header[0:15] == "X-FORWARDED-FOR") {
                    blockIp = to_addr(split_string(header[19:], /,/)[0]);
                }
            }
        } else {
            blockIp = c\$id\$orig_h;
        }
        SumStats::observe("HTTP 40X Response",
            [\$host=blockIp, \$str=cat(c\$id\$resp_h)],
            SumStats::Observation(\$num=1));
    }
}

event zeek_init() {
    local r1 = SumStats::Reducer(\$stream="HTTP 40X Response",
        \$apply=set(SumStats::SUM));

    SumStats::create([\$name="Finding crawlers",
        \$epoch = 1min,
        \$reducers = set(r1),
        \$threshold = 10.0,
        \$threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["HTTP 40X Response"]\$sum;
        },
        \$threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            print fmt("%s attempted crawling %s %s times", key\$host, key\$str, result["HTTP 40X Response"]\$sum);
            NetControl::drop_address_catch_release(key\$host);
        }]);
}
EOF

cat <<EOF > /nsm/zeek/share/zeek/base/frameworks/netcontrol/plugins/pfblock.zeek
module NetControl;

export {
    ## Instantiates the plugin.
    global create_pfblock: function(argument: string) : PluginState;
}

function pfblock_name(p: PluginState) : string
    {
    return "NetControl pfblock plugin";
    }

function pfblock_add_rule_fun(p: PluginState, r: Rule) : bool
    {
    event NetControl::rule_added(r, p);
    local command = "/usr/local/bin/handle-fw.py block " + split_string(cat(r\$entity\$ip), /\//)[0];
    system(command);
    return T;
    }

function pfblock_remove_rule_fun(p: PluginState, r: Rule, reason: string &default="") : bool
    {
    event NetControl::rule_removed(r, p);
    local command = "/usr/local/bin/handle-fw.py release " + split_string(cat(r\$entity\$ip), /\//)[0];
    system(command);
    return T;
    }

global pfblock_plugin = Plugin(
    \$name = pfblock_name,
    \$can_expire = F,
    \$add_rule = pfblock_add_rule_fun,
    \$remove_rule = pfblock_remove_rule_fun
    );

function create_pfblock(argument: string) : PluginState
    {
    local p = PluginState(\$plugin=pfblock_plugin);

    return p;
    }
EOF

sudo sh -c 'echo "@load policy/misc/gcloud-catch-release" >> /nsm/zeek/share/zeek/site/local.zeek'

sudo sed -i 's/eth0/ens4/g' /nsm/zeek/etc/node.cfg
sudo /usr/local/bin/zeekctl install
sudo /usr/local/bin/zeekctl start