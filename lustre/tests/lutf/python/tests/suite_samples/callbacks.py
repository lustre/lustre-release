from lnet_cleanup import clean_lnet
from lustre_cleanup import clean_lustre

def lutf_clean_setup():
	clean_lustre()
	clean_lnet()
