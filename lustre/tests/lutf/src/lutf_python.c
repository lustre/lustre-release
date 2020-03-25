#include <Python.h>
#include <netinet/in.h>
#include "lutf.h"
#include "lutf_python.h"
#include "lutf_listener.h"

extern lutf_config_params_t g_lutf_cfg;
bool g_py_inited = false;

static char *get_path_segment(char *path, int *len, char **more)
{
	char *found = strchr(path, ':');
	char *str = path;

	if (!found) {
		*more = NULL;
		*len = strlen(str);
		return str;
	}

	*len = found - str;
	if (*(found + 1) == '\n')
		*more = NULL;
	else
		*more = found + 1;

	return str;
}

static void python_run_interactive_shell(void)
{
	char buf[MAX_STR_LEN + 20];
	char segment[MAX_STR_LEN];
	char *seg;
	char *more = g_lutf_cfg.py_path;
	int len = 0;
	lutf_rc_t rc;

	PyRun_SimpleString("import code\n");
	PyRun_SimpleString("import os\n");
	PyRun_SimpleString("import sys\n");
	PyRun_SimpleString("import readline\n");

	/* all other paths are figured out within python */
	snprintf(buf, MAX_STR_LEN,
		"sys.path.append(os.path.join('%s', 'python', 'infra'))",
		g_lutf_cfg.lutf_path);
	PyRun_SimpleString(buf);

	snprintf(buf, MAX_STR_LEN,
		"sys.path.append(\"%s/src\")\n",
		g_lutf_cfg.lutf_path);
	PyRun_SimpleString(buf);

	while (more != NULL) {
		seg = get_path_segment(more, &len, &more);
		snprintf(segment, len+1, "%s", seg);
		segment[len] = '\0';
		snprintf(buf, sizeof(buf),
			"sys.path.append(\"%s\")\n", segment);
		PyRun_SimpleString(buf);
	}

	PyRun_SimpleString("import lutf\n");
	PyRun_SimpleString("from lutf import me,suites,"
			   "agents,dumpGlobalTestResults,R,A,I,X\n");

	g_py_inited = true;

	if (g_lutf_cfg.shell == EN_LUTF_RUN_BATCH &&
	    g_lutf_cfg.l_info.type == EN_LUTF_MASTER) {
		char *pattern = g_lutf_cfg.pattern;

		PDEBUG("Running in Batch mode. Checking Agents are connected");

		rc = wait_for_agents(g_lutf_cfg.agents, 20);
		if (rc == EN_LUTF_RC_TIMEOUT) {
			PERROR("Not all agents connected. Aborting tests");
			return;
		}

		/* update the LUTF internal database */
		PyRun_SimpleString("agents.reload()");
		PDEBUG("Agents reloaded. Dumping");
		PyRun_SimpleString("agents.dump()");

		if (g_lutf_cfg.script && strlen(g_lutf_cfg.script) > 0) {
			snprintf(buf, MAX_STR_LEN,
				 "suites['%s'].scripts['%s'].run()",
				 g_lutf_cfg.suite,
				 g_lutf_cfg.script);
		} else if (g_lutf_cfg.suite && strlen(g_lutf_cfg.suite) > 0) {
			snprintf(buf, MAX_STR_LEN,
				 "suites['%s'].run('%s')",
				 g_lutf_cfg.suite, pattern);
		} else {
			snprintf(buf, MAX_STR_LEN,
				 "suites.run('%s')", pattern);
		}
		PDEBUG("%s", buf);
		PyRun_SimpleString(buf);
		snprintf(buf, MAX_STR_LEN,
			 "dumpGlobalTestResults('%s')", g_lutf_cfg.results_file);
		PDEBUG("%s", buf);
		PyRun_SimpleString(buf);
		PDEBUG("Shutting down the LUTF");
		PyRun_SimpleString("me.exit()");
		lutf_listener_shutdown();
		return;
	} else if (g_lutf_cfg.shell == EN_LUTF_RUN_INTERACTIVE) {
		int rc;
		char *intro;

		PDEBUG("Running in Interactive mode");
		/*
		 * start an independent shell
		 * Since we imported all the necessary modules to start in
		 * the main interpreter, copying the globals should copy
		 * them in the interactive shell.
		 */
		PyRun_SimpleString("vars = globals().copy()\n");
		PyRun_SimpleString("vars.update(locals())\n");
		PyRun_SimpleString("shell = code.InteractiveConsole(vars)\n");
		PyRun_SimpleString("shell.push('sys.ps1 = \"lutf>>> \"')\n");
		PyRun_SimpleString("shell.push('sys.ps2 = \"lutf... \"')\n");

		/* import base lutf module */
		g_py_inited = true;
		intro = "shell.interact(\"Welcome to the Lustre Unit Test Framework (LUTF)\\n\""
			"\"Convenience Functions: R() = dumpGlobalTestResults(), A() = agents.dump(), I() = me.dump_intfs(), X() = me.exit()\")";
		rc = PyRun_SimpleString(intro);
		if (rc)
			goto python_shutdown;
	} else {
		/* run the telnet server. This becomes our main process
		 * now
		 */
		PDEBUG("Running in Daemon mode");
		sprintf(segment, "fname = os.path.join('%s', '%s')\n",
			g_lutf_cfg.lutf_path, OUT_PY_LOG);
		if (PyRun_SimpleString(segment)) {
			PERROR("Failed to create log file");
			goto python_shutdown;
		}
		sprintf(segment, "logfile = open(fname, 'w')\n");
		if (PyRun_SimpleString(segment)) {
			PERROR("Failed to open log file");
			goto python_shutdown;
		}
		if (PyRun_SimpleString("sys.stdout = sys.stderr = logfile\n")) {
			PERROR("Failed to redirect stdout and stderr");
			goto python_shutdown;
		}
		if (PyRun_SimpleString("from lutf_telnet_sr import LutfTelnetServer\n")) {
			PERROR("Failed to import LutfTelnetServer");
			goto python_shutdown;
		}
		sprintf(segment, "tns = LutfTelnetServer(%d)\n",
			g_lutf_cfg.l_info.hb_info.agent_telnet_port);
		if (PyRun_SimpleString(segment)) {
			PERROR("Failed to instantiate LutfTelnetServer");
			goto python_shutdown;
		}
		if (PyRun_SimpleString("tns.run()\n")) {
			PERROR("Failed to run LutfTelnetServer instance");
			goto python_shutdown;
		}
		if (PyRun_SimpleString("logfile.close()")) {
			PERROR("Failed to close logfile");
			goto python_shutdown;
		}
python_shutdown:
		PERROR("Exiting the python interpreter");
	}
	g_py_inited = false;
	lutf_listener_shutdown();
}

/*
 * gcc py.c -o py -I/usr/local/include/python2.7
 * -L/usr/local/lib/python2.7/config -lm -ldl -lpthread -lutil -lpython2.7
 */
lutf_rc_t python_init(void)
{
	wchar_t program[5];

	swprintf(program, 3, L"%hs", "lutf");

	//char *path;
	//char new_path[MAX_STR_LEN];
	Py_SetProgramName(program);
	//char *py_args[1];

	//py_args[0] = argv[0];

	Py_Initialize();

	//sprintf(new_path, "%s:%s", path, script_path);
	//PySys_SetPath(new_path);
	//path = Py_GetPath();

	python_run_interactive_shell();
	PDEBUG("Python finalizing");

	Py_Finalize();

	PDEBUG("Python finalized");

	return EN_LUTF_RC_OK;
}

lutf_rc_t python_handle_rpc_request(char *rpc)
{
	lutf_rc_t rc = EN_LUTF_RC_OK;
	PyGILState_STATE gstate;
	PyObject *handle_rpc_req;
	PyObject *lutf;
	PyObject *me;
	PyObject *str;
	PyObject *args;
	PyObject *result;

	if (!g_py_inited)
		return EN_LUTF_RC_PY_SCRIPT_FAIL;

	PDEBUG(rpc);

	gstate = PyGILState_Ensure();

	str = PyUnicode_FromString((char*)"lutf");
	lutf = PyImport_Import(str);
	me = PyObject_GetAttrString(lutf, (char*)"me");
	handle_rpc_req = PyObject_GetAttrString(me, (char*)"handle_rpc_req");
	args = PyTuple_Pack(1, PyUnicode_FromString(rpc));
	result = PyObject_CallObject(handle_rpc_req, args);

	if (!result)
		PDEBUG("handle_rpc_req() didn't return any values");

	PyGILState_Release(gstate);

	return rc;
}

