import coloredlogs, logging

def get_logger(name, no_log_file=False, stream_level='DEBUG'):
    """
    setup logger
    """ 
    
    # setup logging
    LOG = logging.getLogger(name)
    coloredlogs.install(level=logging.DEBUG, logger=LOG)

    # set format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # first handler for the file
    if no_log_file == False:
        
        fh = logging.FileHandler('app.log')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)

        #attach fh handler to LOG
        LOG.addHandler(fh)

    #second handler for screen
    sh = logging.StreamHandler()
    if stream_level == 'DEBUG':
        sh.setLevel(logging.DEBUG)
    else:
        sh.setLevel(logging.INFO)
    sh.setFormatter(formatter)

    # Avoid propagation to root logger (to avoid double print on screen)
    LOG.propagate = False

    return LOG