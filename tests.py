'''Testing module for blacklist.bro.'''

import unittest
import subprocess as sub
import time
import os
from mininet.topo import SingleSwitchTopo
from mininet.node import RemoteController
from mininet.net import Mininet

class TestBro(unittest.TestCase):
    '''Class to set up Mininet and Faucet, and test that bro can block
    given ips.'''
    @classmethod
    def setUpClass(cls):
        '''Add blocked addresses for testing.'''
        with open('block_list.data', 'a') as block_list:
            block_list.write('\n10.0.0.5\ttest\n10.0.0.2\twww.google.com')

    def setUp(self):
        '''Initialise faucet, mininet and bro.'''
        os.system("pkill -f \"faucet.py\"")
        os.system("python update_acls.py clear")
        self.faucet = sub.Popen('../startfaucet', stderr=sub.PIPE)
        while (self.faucet.stderr.readline() !=
               'instantiating app ryu.controller.ofp_handler of OFPHandler\n'):
            pass
        self.net = Mininet(topo=SingleSwitchTopo(4), autoSetMacs=True, controller=RemoteController)
        self.net.addNAT().configDefault()
        self.net.start()
        s1 = self.net.get('s1')
        s1.cmd('ovs-vsctl set bridge s1 protocols=OpenFlow13')
        self.bro = sub.Popen('./startbro', stderr=sub.PIPE)
        self.bro.stderr.readline()
        time.sleep(2)

    def test_ping(self):
        '''Ping between two hosts to make sure mininet is working.'''
        h1, h3 = self.net.get('h1', 'h3')
        self.assertEqual(self.net.ping((h1, h3)), 0.0)

    def test_ping2(self):
        '''Ping a host blocked by another test to check the acls are cleared properly.'''
        h1, h2 = self.net.get('h1', 'h2')
        self.assertEqual(self.net.ping((h1, h2)), 0.0)

    def test_block_ip(self):
        '''Ping a blacklisted host then ping again to check it's blocked correctly.'''
        h1, nat0 = self.net.get('h1', 'nat0')
        self.assertEqual(self.net.ping((h1, nat0)), 0.0)
        time.sleep(2)
        self.assertEqual(self.net.ping((h1, nat0)), 100.0)

    def test_block_dns(self):
        '''Send a dns request to a blacklisted url and then check the corresponding ip
        is blocked.'''
        h1, h2 = self.net.get('h1', 'h2')
        print h1.cmd('dig @8.8.8.8 +vc www.google.com')
        time.sleep(2)
        self.assertEqual(self.net.ping((h1, h2)), 100.0)

    def tearDown(self):
        '''Stop bro and mininet and faucet.'''
        self.bro.terminate()
        self.net.stop()
        self.faucet.terminate()

    @classmethod
    def tearDownClass(cls):
        '''Reset the blocklist by redownloading it.'''
        os.system("./update_blocked")

if __name__ == '__main__':
    unittest.main()
