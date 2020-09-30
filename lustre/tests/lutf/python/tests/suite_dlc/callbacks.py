from lnet_cleanup import clean_lnet
from lustre_cleanup import clean_lustre
import logging

def lutf_clean_setup():
	logging.critical("calling lutf_clean_setup()")
	clean_lustre()
	clean_lnet()
