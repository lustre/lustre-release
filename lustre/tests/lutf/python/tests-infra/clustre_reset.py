from lustre_cleanup import clean_lustre
from lnet_cleanup import clean_lnet

def lutf_clean_setup():
	clean_lustre()
	clean_lnet()
