

def reliablebroadcast(sid, pid, N, t, leader, input, predicate, receive, send):
    """
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int t: maximum number of malicious nodes , ``N >= 3t + 1``
    :param int leader: ``0 <= leader < N``
    :param input: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::
            (i, (tag, ...)) = receive()

        where ``tag`` is one of ``{"PROPOSE", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m``
    """
    
    def multicast(o):
        for i in range(N):
            send(i, o)
    '''
    # TEST: malicious node pretends to be a broadcaster and send proposal
    # fixed leader = 0
    if pid == 2:
        multicast(("PROPOSE", 7))'''

    if pid == leader:
        m = input()  # block until an input is received

        # TEST: malicious broadcaster does not send anything
        multicast(("PROPOSE", m))
        '''
        # TEST: malicious broadcaster sends the proposal to subset of nodes
        for i in range(N):
            if i % 2 == 0:
                send(i, ("PROPOSE", m))'''
        '''
        # TEST: malicious broadcaster sends diff proposals to diff nodes
        for i in range(N):
                if i % 2 == 0:
                    send(i, ("PROPOSE", 6))
                else:
                    send(i, ("PROPOSE", m))'''

    num_echo_per_message = {}
    num_ready_per_message = {}
    sent_ready = False

    while True:  # main receive loop
        sender, msg = receive()

        if msg[0] == 'PROPOSE':
            (_, proposal) = msg
            #proposal = proposal
            if sender != leader:
                print("PROPOSE message from other than leader:", sender)
                continue
            if predicate(proposal):
                multicast(("ECHO", proposal))

        if msg[0] == 'ECHO':
            (_, m) = msg
            if m in num_echo_per_message:
                num_echo = num_echo_per_message[m]
                num_echo_per_message[m] = num_echo + 1
            else:
                num_echo_per_message[m] = 1

            if num_echo_per_message[m] == 2*t+1:
                if not sent_ready:
                    multicast(("READY", m))
                    sent_ready = True

        if msg[0] == "READY":
            (_, m) = msg
            if m in num_ready_per_message:
                num_ready = num_ready_per_message[m]
                num_ready_per_message[m] = num_ready + 1
            else:
                num_ready_per_message[m] = 1

            if num_ready_per_message[m] == t+1:
                if not sent_ready:
                    multicast(("READY", m))
                    sent_ready = True

            if num_ready_per_message[m] == 2*t+1:
                return m
