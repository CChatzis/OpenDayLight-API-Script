![python version:27.15](https://img.shields.io/badge/python-2.7.15-green) ![odl version:BoronSR4](https://img.shields.io/badge/OpenDayLight-BoronSR4-green) 

# OpenDayLight-API-Script
Python script, that uses the OpayDayLIght API, in order to display and even edit topology info.


## Requirements
* [Python 2.7.15](https://www.python.org/downloads/release/python-2715/)
* [OpenDayLight 0.5.4-BoronSR4](https://nexus.opendaylight.org/content/repositories/public/org/opendaylight/integration/distribution-karaf/0.5.4-Boron-SR4/)
* [Mininet](http://mininet.org/download/)

## How to use
1. Run OpenDayLight
2. Run Mininet and connect it to the ODL Controller
i.e.
    `$ sudo mn --topo=tree,2 --controller=remote,ip=<CONTROLLER_IP>`
3. Make sure OpenDayLight and Mininet are connected by checking the **Topology** Tab.You should be able to see the switches and flows of your topology.
4. Change Global Variables to your controller's info in odl_script.py. (baseUrl,baseIP)
5. Run Script using `$ python odl_script.py`
6. Enter any option 1-14 or 0 to exit
