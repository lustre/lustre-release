// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2025, DataDirect Networks Inc, all rights reserved.
 */
/*
 * llapi interface for handling project IDs
 *
 * Author: Andreas Dilger <adilger@whamcloud.com>
 * Author: Frederick Dilger <fdilger@whamcloud.com>
 */

/* /etc/projid format:
 *
 *  # comment text until the end of the line
 *  projname:projid[:description:user_list:group_list:attributes]
 *
 * The fields are defined as follows:
 *
 *  projname - The name of the project up to 31 characters. The name must be
 *    a string that consists of alphanumeric characters, underline (_)
 *    characters, hyphens (-), and periods (.). The period, which is reserved
 *    for projects with special meaning to the operating system, can only be
 *    used in the names of default projects for users. projname cannot contain
 *    colons (:) whitespace, or other special characters.  Present in XFS.
 *
 *  projid - The project's unique numerical ID (PROJID) within the system.
 *    The maximum value of the projid field is 4294967294.
 *
 * Fields after projname and projid are proposed and NOT CURRENTLY IMPLEMENTED.
 * These fields are based on the Solaris /etc/project format, as described in:
 * https://docs.oracle.com/cd/E19044-01/sol.containers/817-1592/rmtaskproj-12/index.html
 *
 *  description - A very brief description of the project.
 *    May not contain colon ':' or '#' or control characters. Not in XFS.
 *
 *  user-list - A comma-separated list of users who are allowed in the
 *    project. Wildcards can be used in this field. An asterisk (*) allows
 *    all users to join the project. An exclamation point followed by an
 *    asterisk (!*) excludes all users from the project. An exclamation
 *    mark (!) followed by a username excludes the specified user from
 *    the project. Not in XFS.
 *
 *  group-list - A comma-separated list of groups of users who are allowed
 *    in the project. Wildcards can be used in this field. An asterisk (*)
 *    allows all groups to join the project. An exclamation point followed
 *    by an asterisk (!*) excludes all groups from the project. An exclamation
 *    mark (!) followed by a group name excludes the specified group from
 *    the project. Not in XFS.
 *
 *  attributes - A semicolon-separated list of name[=value] pairs, such as
 *    resource controls name is an arbitrary string that specifies the
 *    object-related attribute, and value is the optional value for that
 *    attribute. In the name-value pair, names are restricted to letters,
 *    digits, underscores, and periods. A period is conventionally used as
 *    a separator between the categories and subcategories of the resource
 *    control (rctl). The first character of an attribute name must be a
 *    letter. The name is case sensitive. Values can be structured by using
 *    commas and parentheses to establish precedence. A semicolon is used
 *    to separate name-value pairs. A semicolon cannot be used in a value
 *    definition. A colon is used to separate project fields. A colon cannot
 *    be used in a value definition.
 */

#include <lustre/lustreapi.h>
#include <stdio.h>

#define LPH_MAGIC 0x9506ec71d95061dull
#define MAXPROJNAME 32

struct ll_project_handle {
	__u64		 lph_magic;
	FILE		*lph_file;
};

/* open project mapping file and maintain state across calls in @hdl */
int llapi_project_open(const char *name, struct ll_project_handle **hdl,
		       char *mode)
{
	const char *projid_file = "/etc/projid";
	char *projid_env;
	struct ll_project_handle *lph;
	FILE *file;
	int rc = 0;

	if (name) {
		if (name[0] == '\0') {
			errno = EINVAL;
			return -EINVAL;
		}
		projid_file = name;
	}

	/* allow overriding the project mapping filename for testing */
	projid_env = secure_getenv("LIBLUSTREAPI_PROJID_FILE");
	if (projid_env)
		projid_file = projid_env;
	file = fopen(projid_file, mode);
	if (!file)
		return -errno;

	lph = calloc(1, sizeof(*lph));
	if (!lph) {
		rc = -ENOMEM;
		goto out_close;
	}

	lph->lph_magic = LPH_MAGIC;
	lph->lph_file = file;

	*hdl = lph;

	return rc;

out_close:
	fclose(file);

	return rc;
}

/* close project mapping file and release state in @hdl */
int llapi_project_close(struct ll_project_handle *hdl)
{
	int rc = 0;

	if (!hdl || hdl->lph_magic != LPH_MAGIC) {
		rc = -EINVAL;
		goto out;
	}

	if (hdl->lph_file && fclose(hdl->lph_file))
		rc = -errno;

	free(hdl);

out:
	if (rc)
		errno = -rc;
	return rc;
}

/* populate remaining fields in @lprj from open @hdl based on valid fields */
int llapi_project_get(struct ll_project_handle *hdl, struct ll_project *lprj)
{
	unsigned int prjid;
	int rc = -ENOENT;
	char *line = NULL;
	size_t len = 0;

	/* check that at least name or id is filled out in @lprj */
	if (!(lprj->lprj_valid & (LPRJ_VALID_NAME|LPRJ_VALID_ID)))
		return -EINVAL;

	/* Reset file pointer to the beginning of the file */
	rewind(hdl->lph_file);

	while (getline(&line, &len, hdl->lph_file) != -1) {
		char name[32];
		char comment[256];
		char users[256];
		char groups[256];
		char attrs[256];
		int num;

		/* Skip empty lines and comment lines starting with '#' */
		if (line[0] == '\n' || line[0] == '#')
			continue;

		/* projname:projid[:comment:user_list:group_list:attributes] */
		num = sscanf(line,
			    "%31[^:]:%u:%255[^:]:%255[^:]:%255[^:]:%255[^\n]",
			    name, &prjid, comment, users, groups, attrs);
		if (num < 2)
			continue;

		/* check if the valid fields are matching */
		if ((lprj->lprj_valid & LPRJ_VALID_NAME) &&
		    strcmp(lprj->lprj_projname, name) == 0) {
			lprj->lprj_projid = prjid;
			lprj->lprj_valid |= LPRJ_VALID_ID;
			rc = 0;
			break;
		}
		if ((lprj->lprj_valid & LPRJ_VALID_ID) &&
		    lprj->lprj_projid == prjid) {
			strncpy(lprj->lprj_projname, name,
				sizeof(lprj->lprj_projname));
			lprj->lprj_valid |= LPRJ_VALID_NAME;
			rc = 0;
			break;
		}
	}

	/* fill in the other fields here */

	if (line)
		free(line);

	return rc;
}

/* free any allocated memory in @lprj */
int llapi_project_put(struct ll_project_handle *hdl, struct ll_project *lprj,
		      int flags)
{
	return 0;
}

/* populate fields in @lprj based on requested @name from open @hdl */
int llapi_project_fgetnam(struct ll_project_handle *hdl,
			  struct ll_project *lprj, const char *name)
{
	if (!lprj || !(lprj->lprj_valid & LPRJ_VALID_SIZE) ||
	    lprj->lprj_size < offsetof(typeof(*lprj), lprj_projname[MAXPROJNAME]))
		return -EINVAL;

	snprintf(lprj->lprj_projname, sizeof(lprj->lprj_projname), "%s", name);
	lprj->lprj_valid |= LPRJ_VALID_NAME;

	return llapi_project_get(hdl, lprj);
}

/* populate fields in @lprj based on requested @name */
int llapi_project_getnam(struct ll_project *lprj, const char *name)
{
	struct ll_project_handle *hdl = NULL;
	int rc = -ENOENT;

	rc = llapi_project_open(NULL, &hdl, "r");
	if (rc)
		goto out;

	rc = llapi_project_fgetnam(hdl, lprj, name);

	llapi_project_close(hdl);

out:
	return rc;
}

/* populate fields in @lprj based on requested @prjid from open @hdl */
int llapi_project_fgetprjid(struct ll_project_handle *hdl,
			 struct ll_project *lprj, const unsigned int prjid)
{
	if (!lprj || !(lprj->lprj_valid & LPRJ_VALID_SIZE) ||
	    lprj->lprj_size < offsetof(typeof(*lprj), lprj_projname[32]))
		return -EINVAL;

	lprj->lprj_projid |= prjid;
	lprj->lprj_valid |= LPRJ_VALID_ID;

	return llapi_project_get(hdl, lprj);
}

/* populate fields in @lprj based on requested @prjid */
int llapi_project_getprjid(struct ll_project *lprj, __u32 prjid)
{
	struct ll_project_handle *hdl = NULL;
	int rc;

	rc = llapi_project_open(NULL, &hdl, "r");
	if (rc)
		return rc;

	if (!lprj || !(lprj->lprj_valid & LPRJ_VALID_SIZE) ||
	    lprj->lprj_size < offsetof(typeof(*lprj), lprj_projname[32])) {
		rc = -EINVAL;
		goto out;
	}

	rc = llapi_project_fgetprjid(hdl, lprj, prjid);

out:
	llapi_project_close(hdl);
	return rc;
}
