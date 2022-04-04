from charm.toolbox.ecgroup import ECGroup, ZR, serialize, deserialize
from charm.toolbox.eccurve import prime192v1
import gevent
from gevent import Greenlet
from gevent.queue import Queue

group = ECGroup(prime192v1)

def rbc(pid, N, t, leader, input, g, receive, send):
    def multicast(o):
        for i in range(N):
            send(i, o)

    if pid == leader:
        m = input()  # block until an input is received

        # TEST: malicious dealer sends diff commitments to diff nodes
        '''m_copy = m
        m_copy[0] = g ** group.init(ZR, 9)

        for i in range(N):
            if i % 2 == 0:
                send(i, ("PROPOSE", m))
            else:
                send(i, ("PROPOSE", m_copy))'''
        # normal
        multicast(("PROPOSE", m))

    num_echo_per_v = []
    num_ready_per_v = []
    sent_ready = False
    sent_echo = False

    def is_v_in_list(v_, list_):
        for i in range(len(list_)):
            li = list_[i]
            if li[0] == v_:
                return i  # index of the list in num_echo_per_v_
        else:
            return None

    propose_msg_v = None
    share_msg_pi = None

    while True:  # main receive loop
        while propose_msg_v is None or share_msg_pi is None:  # wait until each node gets both SHARE and PROPOSE
            sender, msg = receive()
            # print("SHARE or PROPOSE --> RBC( ) --> node #", pid, " got message = ", msg[0], " of type = ", type(msg[1]))

            if msg[0] == 'SHARE':
                share_msg_pi = msg[1]
                if sender != leader:
                    share_msg_pi = None
                    print("SHARE message from other than leader:", sender)
                    continue
            elif msg[0] == 'PROPOSE':
                propose_msg_v = msg[1]
                if sender != leader:
                    propose_msg_v = None
                    print("PROPOSE message from other than leader:", sender)
                    continue

        # predicate --> calculate g^P(i) and compare it with g^share_msg_pi
        predicate = False

        g_Pi = None
        x = group.init(ZR, pid+1)
        for i in range(len(propose_msg_v)):
            v_i = propose_msg_v[i]
            if i == 0:
                g_Pi = v_i ** (x ** group.init(ZR, i))
            else:
                g_Pi = g_Pi * (v_i ** (x ** group.init(ZR, i)))
        if g_Pi == g ** share_msg_pi:
            predicate = True

        #print("predicate value = ", predicate)
        if predicate and not sent_echo:
            #print("RBC() --> NODE =", pid, " is sending (ECHO)")
            multicast(("ECHO", propose_msg_v))
            sent_echo = True

        sender, msg = receive()  # get ECHO, READY messages
        #print("ECHO or READY --> RBC( ) --> node #", pid, " got message = ", msg[0], " of type = ", type(msg[1]))

        if msg[0] == 'ECHO':
            (_, v) = msg

            idx = is_v_in_list(v, num_echo_per_v)
            if idx is None:
                num_echo_per_v.append([v, 1])  # this is the first time seeing v
                idx = len(num_echo_per_v) - 1
            else:
                curr_freq = num_echo_per_v[idx][1]
                num_echo_per_v[idx][1] = curr_freq + 1

            if num_echo_per_v[idx][1] == 2*t+1:
                if not sent_ready:
                    #print("RBC() --> NODE =", pid, " is sending (READY) from 2t+1 ECHO's")
                    multicast(("READY", v))
                    sent_ready = True

        if msg[0] == "READY":
            (_, v) = msg

            idx = is_v_in_list(v, num_ready_per_v)
            if idx is None:
                num_ready_per_v.append([v, 1])  # this is the first time seeing v
                idx = len(num_ready_per_v) - 1
            else:
                curr_freq = num_ready_per_v[idx][1]
                num_ready_per_v[idx][1] = curr_freq + 1

            if num_ready_per_v[idx][1] == t + 1:
                if not sent_ready:
                    #print("RBC() --> NODE =", pid, " is sending (READY) from t+1 READY's")
                    multicast(("READY", v))
                    sent_ready = True
            if num_ready_per_v[idx][1] == 2*t + 1:
                #print("RETURNING V HERE  = ")
                #print(v)
                return v, share_msg_pi


def poly_evaluate(coeffs, x):
    '''px = coeffs[0]  # init to s
    for j in range(1, len(coeffs)):
        px = px + coeffs[j] * (x ** j)
    #print("pi = ", px)
    return px'''
    result = group.init(ZR, 0)
    power_of_i = group.init(ZR, 1)
    for i in range(0,  len(coeffs)):
        result = result + coeffs[i] * power_of_i
        power_of_i = power_of_i * x
    return result

def avss_share(sid, pid, N, t, g, leader, input, receive, send):
    """Asynchronous Verifiable Secret Sharing

    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int t: maximum number of malicious nodes , ``N >= 3t + 1``
    :param group g: a generator of the elliptic curve group
    :param int leader: ``0 <= leader < N``
    :param input: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::

            (i, (tag, ...)) = receive()
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return commitments and share
    """

    threads = []
    leader_input1 = None
    input1 = None

    if leader == pid:
        leader_input1 = Queue(1)
        input1 = leader_input1.get

    rbc_th = Greenlet(rbc, pid, N, t, leader, input1, g, receive, send)
    threads.append(rbc_th)
    if leader != pid:
        rbc_th.start()

    if leader == pid:
        # get s as input
        s = input()
        #print("leader got secret, which is = ", s)

        # 2 generate rand coeffs
        coeffs = [None] * (t + 1)
        coeffs[0] = s
        for i in range(1, t+1):
            coeffs[i] = group.random(ZR)

        # 3 create v[]
        v = [None] * (t+1)
        for i in range(len(coeffs)):
            v[i] = g ** coeffs[i]

        # 4 RBC
        rbc_th.start()
        # TEST: malicious leader doesn't send anything
        leader_input1.put(v)

        # 5 send ("SHARE", p(i)) to everyone
        threads1 = []
        for i in range(0, N):
            '''
            # TEST: malicious leader sends shares to subset of nodes
            if i % 2 == 0:
                th = Greenlet(send, i, ("SHARE", poly_evaluate(coeffs, i + 1)))
                th.start()
                threads1.append(th)'''

            '''
            # TEST: malicious leader sends incorrect shares to nodes
            th = Greenlet(send, i, ("SHARE", poly_evaluate(coeffs, (i + 2) % N)))
            th.start()
            threads1.append(th)'''


            # normal
            th = Greenlet(send, i, ("SHARE", poly_evaluate(coeffs, i + 1)))
            th.start()
            threads1.append(th)
        gevent.joinall(threads1)

    gevent.joinall(threads)
    #print("END OF avss_share(), threads[0] = ", threads[0].value[0], threads[0].value[1])
    return threads[0].value[0], threads[0].value[1]


def avss_reconstruct(sid, pid, N, t, g, input, receive, send) -> ZR:
    """Asynchronous Verifiable Secret Sharing
    
    :param string sid: session id
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int t: maximum number of malicious nodes , ``N >= 3t + 1``
    :param group g: a generator of the elliptic curve group
    :param input: func:`input()` is called to wait for the input value
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::
            (i, (tag, ...)) = receive()
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return reconstructed secret 
    """

    v, pi = input()

    for j in range(N):
        '''
        # TEST: malicious nodes send incorrect reconstruct shares
        if pid == 0:
            send(j, ("RECONSTRUCT", group.random()))
        else:
            send(j, ("RECONSTRUCT", pi))'''

        '''
        # TEST: malicious nodes don't send reconstruct
        if pid != 0:
            send(j, ("RECONSTRUCT", pi))'''

        '''
        # TEST: malicious nodes don't send reconstruct to all nodes
        if pid == 0:
            if j != 2:
                send(j, ("RECONSTRUCT", pi))
        else:
            send(j, ("RECONSTRUCT", pi))'''

        # normal
        send(j, ("RECONSTRUCT", pi))

    shares = []
    while True:
        sender, msg = receive()

        if msg[0] == 'RECONSTRUCT':
            (_, pi) = msg

            valid = False

            g_Pi = None
            x = group.init(ZR, sender + 1)
            for i in range(len(v)):
                v_i = v[i]
                if i == 0:
                    g_Pi = v_i ** (x ** group.init(ZR, i))
                else:
                    g_Pi = g_Pi * (v_i ** (x ** group.init(ZR, i)))
            if g_Pi == g ** pi:
                valid = True

            if valid:
                shares.append((sender+1, pi))

            if len(shares) >= t+1:
                break

    secret = group.init(ZR, 0)
    for (sender, pi) in shares:
        cidx = group.init(ZR, 1)
        for sender_other,  _ in shares:
            if sender_other != sender:
                sender1 = group.init(ZR, sender)
                sender_other1 = group.init(ZR, sender_other)
                cidx = cidx * (sender_other1 * (sender_other1 - sender1).__invert__())
        secret = secret + pi * cidx
    return secret
