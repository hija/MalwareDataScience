import argparse
import os
import re
import subprocess
import networkx
import pydot #Friendly reminder to myself, you do not need pygraphviz - pydot is enough!
from networkx.drawing.nx_pydot import write_dot

# The lines which have been commented out can be used to use matplotlib
# However, the graph is quite ugly then...

#import matplotlib
#import matplotlib.pyplot as plt

valid_hostname_suffixes = ['com', 'de', 'org', 'eu', 'net', 'co', 'us']
hostname_to_app = dict()

def build_graph(path):

    # Analyzing PE-Files
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            if is_pefile(os.path.join(path, file)):
                print('[*] Analyzing PE-File', file)

                strings_in_file = get_strings(os.path.join(path, file))
                candidate_hostnames = re.findall( r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', strings_in_file)
                valid_hostnames = list(filter(lambda hostname: hostname.split(".")[-1].lower() in valid_hostname_suffixes, candidate_hostnames))

                for hostname in valid_hostnames:
                    current_apps_for_hostname = hostname_to_app.get(hostname, [])
                    if not file in current_apps_for_hostname:
                        current_apps_for_hostname.append(file)
                        hostname_to_app[hostname] = current_apps_for_hostname

    ### Build graph
    network = networkx.Graph()
    added_apps = []
    #colors = []

    for key,value in hostname_to_app.items():
        network.add_node(key, penwidth=5)
        #colors.append('red')
        for app in value:
            if not app in added_apps:
                network.add_node(app, penwidth=3)
                #colors.append('blue')
            network.add_edge(key, app, penwidth=2)
    write_dot(network, "vis.dot")
    #networkx.drawing.nx_pylab.draw(network, node_color = colors, with_labels = True)
    #plt.show()

def get_strings(filepath):
    strings = subprocess.Popen(['strings', '-u', '-nobanner', '{}'.format(filepath)], stdout=subprocess.PIPE).communicate()[0]
    return strings.decode('utf-8')

def is_pefile(filepath):
    return open(filepath, 'rb').read(2) == b'MZ'

parser = argparse.ArgumentParser(description='Creates a dotfile for http-network from files')
parser.add_argument('path', help='The path in which the pe files are stored')
args = parser.parse_args()
build_graph(args.path)
