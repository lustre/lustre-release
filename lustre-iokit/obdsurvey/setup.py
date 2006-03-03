from distutils.core import setup
setup(name='lustre-iokit',
      py_modules=['lustre_obdsurveylib'],
      scripts=['lustre_obdsurvey.py'],
      data_files=[
              ('/usr/share/lustre-iokit', ['README', 'LICENSE'])
              ]
      )
