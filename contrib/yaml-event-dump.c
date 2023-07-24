// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2023 James Simmons <jsimmons@infradead.org>
 *
 * Writing libyaml C code can be very difficult to get right. So I wrote
 * this application that takes a YAML file and creates pseudo user land
 * libyaml C code. This will speed up development greatly. Note its not
 * 100% promised that the YAML config file that works with the libyaml
 * is valid. Please always test your YAML file with http://www.yamllint.com
 *
 * To build this application just run : gcc -lyaml yaml-event-dump.c
 *
 * This application just takes one argument which is the file path to
 * the YAML config file. Example ./a.out lnet.conf
 *
 * Once you run this application against the YAML config file you will
 * see C libyaml pseudocode that using the libyaml API will build
 * a proper YAML document. You can then cut and paste the C code
 * ouput to your C function, thus saving time. At the end of the
 * pseudo code we also prints out the YAML document in the style
 * of the libyaml API.
 */
#include <errno.h>
#include <yaml.h>

int main(int argc, char **argv)
{
	yaml_emitter_t output;
	yaml_parser_t setup;
	yaml_event_t event;
	FILE *file;
	int i = 1;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s /path/to/yaml.conf\n", argv[0]);
		return -1;
	}

	file = fopen(argv[1], "r");
	if (!file)
		return -errno;

	/* Initialize configuration parser */
	rc = yaml_parser_initialize(&setup);
	if (rc == 0)
		return -EINVAL;

	yaml_parser_set_input_file(&setup, file);

	rc = yaml_emitter_initialize(&output);
	if (rc == 0)
		goto free_results;

	yaml_emitter_set_output_file(&output, stdout);

	puts("\tyaml_emitter_t request;");
	puts("\tyaml_event_t event;\n");

	do {
		/* Get the next event. */
		if (!yaml_parser_parse(&setup, &event))
			goto emitter_error;

		switch (event.type) {
		case YAML_STREAM_START_EVENT:
			puts("\tyaml_emitter_open(&request);");
			break;
		case YAML_DOCUMENT_START_EVENT:
			puts("\tyaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);");
			puts("\trc = yaml_emitter_emit(&request, &event);");
			puts("\tif (rc == 0)");
			puts("\t\tgoto emitter_error;");
			puts("");
			break;
		case YAML_DOCUMENT_END_EVENT:
			puts("\tyaml_document_end_event_initialize(&event, 0);");
			/* YAML_STREAM_END_EVENT will be next */
			puts("\trc = yaml_emitter_close(&request);");
			puts("\tif (rc == 0)");
			puts("\t\tgoto emitter_error;");
			puts("");
			break;
		case YAML_ALIAS_EVENT:
			break;
		case YAML_SCALAR_EVENT: {
			char *value = (char *)event.data.scalar.value;

			puts("\tyaml_scalar_event_initialize(&event, NULL,");
			if (!strlen(value)) {
				puts("\t\t\t\t     (yaml_char_t *)YAML_NULL_TAG,");
			} else if (strcasecmp(value, "yes") == 0 ||
				   strcasecmp(value, "no") == 0 ||
				   strcasecmp(value, "true") == 0 ||
				   strcasecmp(value, "false") == 0 ||
				   strcasecmp(value, "on") == 0 ||
				   strcasecmp(value, "off") == 0 ||
				   strcasecmp(value, "y") == 0 ||
				   strcasecmp(value,  "n") == 0) {
				puts("\t\t\t\t     (yaml_char_t *)YAML_BOOL_TAG,");
			} else if (strspn(value, "0123456789abcdefABCDEF") ==
				   strlen(value)) {
				puts("\t\t\t\t     (yaml_char_t *)YAML_INT_TAG,");
			} else {
				puts("\t\t\t\t     (yaml_char_t *)YAML_STR_TAG,");
			}
			//printf("\t\t\t\t     (yaml_char_t *)\"%s\",\n",
			//       event.data.scalar.tag);
			printf("\t\t\t\t     (yaml_char_t *)\"%s\",\n", value);
			printf("\t\t\t\t     strlen(\"%s\"), 1, 0,\n", value);

			switch (event.data.scalar.style) {
			case YAML_PLAIN_SCALAR_STYLE:
				puts("\t\t\t\t     YAML_PLAIN_SCALAR_STYLE);");
				break;
			case YAML_SINGLE_QUOTED_SCALAR_STYLE:
				puts("\t\t\t\t     YAML_SINGLE_QUOTED_SCALAR_STYLE);");
				break;
			case YAML_DOUBLE_QUOTED_SCALAR_STYLE:
				puts("\t\t\t\t     YAML_DOUBLE_QUOTED_SCALAR_STYLE);");
				break;
			case YAML_LITERAL_SCALAR_STYLE:
				puts("\t\t\t\t     YAML_LITERAL_SCALAR_STYLE);");
				break;
			case YAML_FOLDED_SCALAR_STYLE:
				puts("\t\t\t\t     YAML_FOLDER_SCALAR_STYLE);");
				break;
			case YAML_ANY_SCALAR_STYLE:
			default:
				puts("\t\t\t\t     YAML_ANY_SCALAR_STYLE);");
				break;
			}
			puts("\trc = yaml_emitter_emit(&request, &event);");
			puts("\tif (rc == 0)");
			puts("\t\tgoto emitter_error;");
			puts("");
			}
			break;
		case YAML_SEQUENCE_START_EVENT:
			puts("\tyaml_sequence_start_event_initialize(&event, NULL,");
			puts("\t\t\t\t\t     (yaml_char_t *)YAML_SEQ_TAG,");
			printf("\t\t\t\t\t     1, %s);\n",
			       (event.data.sequence_start.style == YAML_BLOCK_SEQUENCE_STYLE) ?
			       "YAML_BLOCK_SEQUENCE_STYLE" : "YAML_FLOW_SEQUENCE_STYLE");
			puts("\trc = yaml_emitter_emit(&request, &event);");
			puts("\tif (rc == 0)");
			puts("\t\tgoto emitter_error;");
			puts("");
			break;
		case YAML_SEQUENCE_END_EVENT:
			puts("\tyaml_sequence_end_event_initialize(&event);");
			puts("\trc = yaml_emitter_emit(&request, &event);");
			puts("\tif (rc == 0)");
			puts("\t\tgoto emitter_error;");
			puts("");
			break;
		case YAML_MAPPING_START_EVENT:
			puts("\tyaml_mapping_start_event_initialize(&event, NULL,");
			puts("\t\t\t\t\t    (yaml_char_t *)YAML_MAP_TAG,"),
			printf("\t\t\t\t\t    1, %s);\n",
			       (event.data.mapping_start.style == YAML_BLOCK_MAPPING_STYLE) ?
			       "YAML_BLOCK_MAPPING_STYLE" : "YAML_FLOW_MAPPING_STYLE");
			puts("\trc = yaml_emitter_emit(&request, &event);");
			puts("\tif (rc == 0)");
			puts("\t\tgoto emitter_error;");
			puts("");
			break;
		case YAML_MAPPING_END_EVENT:
			puts("\tyaml_mapping_end_event_initialize(&event);");
			puts("\trc = yaml_emitter_emit(&request, &event);");
			puts("\tif (rc == 0)");
			puts("\t\tgoto emitter_error;");
			puts("");
		default:
			break;
		}

		/* Emit the event. */
		if (!yaml_emitter_emit(&output, &event))
			goto emitter_error;
	} while (event.type != YAML_STREAM_END_EVENT);

	rc = yaml_emitter_flush(&output);
	if (rc == 0)
		fprintf(stderr, "dump failed\n");

emitter_error:
	yaml_emitter_delete(&output);
free_results:
	yaml_parser_delete(&setup);
	return 0;
}
