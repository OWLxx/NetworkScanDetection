'''
Xin Wen, Project 3, 4
'''
import os
import sys
import argparse
import operator

def main():
    if clArg():  # if in online mode
        log = 'Online Mode'
        buffer = []
        count = 0
        for line in sys.stdin:
            buffer.append(line)
            count += 1
            if count >=200:
                attack_analyze(buffer, log)
                count = 0
    else:  # else analyze from log file
        file_in_current_directory = os.listdir('.')
        log_file = []   # all the log file in current directory
        for files in file_in_current_directory:
            if files[-4:] == '.log':
                log_file.append(files)
        for log in log_file:
            f = open(log, 'r')
            data = f.readlines()
            attack_analyze(data, log)
            f.close()

def clArg(): # check arguments in command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--online', help='Run code in real time', action='store_true')
    args = parser.parse_args()
    if args.online:
        return True
    else:
        return False

def find_ip(lines): # find ip in different lines
    if lines.find('ARP, Request')!=-1:
        lines = lines.split(' ')
        ip_who_has = lines[4]
        index = lines.index('tell')
        ip_tell = lines[index+1][:-1]
        time = lines[0][0:8]
        return ip_who_has, ip_tell,time
    elif(lines.find("ARP, Reply")) != -1:
        reply_ip = lines.split(" ")[3]
        return reply_ip, '', lines[0][0:8]
    elif lines.find('oui') != -1:
        lines = lines.split(' ')
        # print 'ouilines', lines
        ip1 = lines[3]
        ip2 = lines[5][:-1]  # MAC address
        time = lines[0][0:8]
        return ip1, ip2, time
    elif lines.find('IP')!= -1:
        lines = lines.split(' ')
        where_is_dot = [i for i, ltr in enumerate(lines[2]) if ltr == '.']
        if len(where_is_dot) <4: return '', '', ''
        ip1 = lines[2][:where_is_dot[-1]]
        where_is_dot = [i for i, ltr in enumerate(lines[4]) if ltr == '.']
        if len(where_is_dot) <4: return '', '', ''
        ip2 = lines[4][:where_is_dot[-1]]
        time = lines[0][0:8]
        return ip1, ip2, time
    else:

        return '', '', ''

def printing(data, scan_ip, length, flag):  # find nmap type and print on screen
    # data is the input log file
    # scan_ip shows the ip of victim and scanner
    # length is length log file records
    # flag is the number of S or R flag in the file
    # in this program, it can tell nmap scan type -F, -SF and -SS

    for ele in length:
        if length[ele] == 0:
            ip1, ip2 = ele.split(':')
            try:
                del scan_ip[ip1]  # remove 0 length record
            except KeyError: pass
    length = {k: v for k, v in length.iteritems() if v != 0}  # remove 0 length record
    # print 'scan_ip', scan_ip
    # print length, flag
    types = max(flag.iteritems(), key=operator.itemgetter(1))[0]
    if types=='F':
        typ = '-SF'
    elif types == 'S':
        if max(length.values()) >= 1000:  # -F scan usually have less than 500 records, 1000 is a safe threshold value
            typ = '-sS'
        else:
            typ = '-F'
    else:
        typ = 'unknown'
    for ele in scan_ip:
        print '\t -nmap {} from {} to {} at {}'.format(typ, scan_ip[ele][1], ele, scan_ip[ele][0])

def initializing():
    nmap = [] # telling nmap type
    scan_ip = {}
    length = {} # length of scan
    flag = {'S':0, 'R':0,'F' :0}  # flag of scan
    return nmap, scan_ip, length, flag



def attack_analyze(data, log): # input log, analyze if attack exists
    print log, '-->'
    nmap, scan_ip, length, flag = initializing()
    for index, lines in enumerate(data):
        ip1, ip2, time = find_ip(lines)
        # print ip1, ip2
        if lines.find('ARP, Request')!=-1:  # find start
            ip1, ip2, _ = find_ip(lines) # ip1 is victim ip2 is scanner
            if lines.find('(Broadcast)')!= -1: # scanner need to send broadcast
                scan_ip[ip1] = [time, ip2]  # save potential victim, time in the log, and scanner
                if ip1+':'+ip2 not in length:
                    length[ip1+':'+ip2] = 0 # victim/scanner
                try:
                    if max(length.values()) >= 5:
                        printing(data, scan_ip, length, flag) # analyzing scan info and print it
                        nmap, scan_ip, length, flag = initializing() # re-initialize it
                except ValueError: pass
        else:  # find the length of log corresponds to a scan
            # print length.keys(), [ip1+':'+ip2],' ###'
            if ip1+':'+ip2 in length:
                length[ip1+':'+ip2] += 1
            elif ip2+':'+ip1 in length:
                length[ip2+':'+ip1] += 1
        if (lines.find('Flags [S]')!=-1 or lines.find('Flgas [S.]')!=-1):  # find nmap s scan
            flag['S'] += 1  # number of S flag
        elif (lines.find('Flags [R]')!=-1 or lines.find('Flgas [R.]')!=-1):
            flag['R'] += 1
        elif (lines.find('Flags [F]')!=-1 or lines.find('Flgas [F.]')!=-1):
            flag['F'] +=1
        try:
            if log == 'Online Mode' and max(length.values()) >= 2000:
                printing(data, scan_ip, length, flag) # analyzing scan info and print it
                nmap, scan_ip, length, flag = initializing() # re-initialize it
        except ValueError: pass
    try:
        if max(length.values()) >= 5:
            printing(data, scan_ip, length, flag) # analyzing scan info and print it
            nmap, scan_ip, length, flag = initializing() # re-initialize it
    except ValueError: pass

main()