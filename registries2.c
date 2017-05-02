#include <yaml.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <glib.h>
#include <argp.h>

GArray *registries;
GHashTable* hash;
GPtrArray* tmp_values;
char * headers [] = { "secure_registries", "insecure_registries", "block_registries" };
gchar *cur_header = "None";


void add_value_to_tmp_array(char* value){
	g_ptr_array_add(tmp_values, g_strdup(value));
}

void destroy_tmp_array(){
	g_ptr_array_free(tmp_values, TRUE);
}

void add_array_to_hash(char* hash_name){
	// Add the ptr array to the hashmap under hash_name
	g_hash_table_insert(hash, hash_name, tmp_values);
	// Clear the tmp_values ptr array
	g_ptr_array_free(tmp_values, TRUE);
}

bool is_string_header(char* header)
{
	int i;
	for (i=0; i < sizeof(headers)/sizeof(headers[0]); i++ ) {
		if (!strcmp(headers[i], header)){
			return TRUE;
		}
	}
	return FALSE;
}
void printl_utf8(unsigned char *str, size_t length, FILE *stream)
{
	fwrite(str, 1, length, stream);
}

GPtrArray* assemble_array(){
	GPtrArray* store_values = g_ptr_array_new();
	for (guint i = 0; i < tmp_values->len; i++) {
		g_ptr_array_add(store_values, g_ptr_array_index(tmp_values, i));
	}
	// NULL terminate the array
	g_ptr_array_add (store_values, NULL);
	return store_values;
}

void print_yaml_node(yaml_document_t *document_p, yaml_node_t *node, bool header)
{
	unsigned char* heading;
	switch(node->type){

	yaml_node_t *next_node_p;
	// Find start sequences
	case YAML_SEQUENCE_NODE:
		for (yaml_node_item_t *i_node = node->data.sequence.items.start; i_node < node->data.sequence.items.top; i_node++) {

			next_node_p = yaml_document_get_node(document_p, *i_node);
			if (next_node_p)
				print_yaml_node(document_p, next_node_p, FALSE);
		}
		// Add the tmp_array to the hash
		g_hash_table_insert(hash, g_strdup(cur_header), assemble_array());
		destroy_tmp_array();
		cur_header = "None";
		break;

	case YAML_SCALAR_NODE:
		heading = node->data.scalar.value;
		if (header) {
			if (is_string_header((char*) heading)) {
				cur_header = heading;
			}
		}
		else {
			if (cur_header != "None"){
				printf("Current Header: %s\n", cur_header);
				add_value_to_tmp_array(g_strdup((char *)heading));
			}
		}
		break;

	case YAML_MAPPING_NODE:
		for (yaml_node_pair_t *i_node_p = node->data.mapping.pairs.start; i_node_p < node->data.mapping.pairs.top; i_node_p++) {
			next_node_p = yaml_document_get_node(document_p, i_node_p->key);
			if (next_node_p) {
				print_yaml_node(document_p, next_node_p, TRUE);
			}
			next_node_p = yaml_document_get_node(document_p, i_node_p->value);
			if (next_node_p) {
				print_yaml_node(document_p, next_node_p, FALSE);
			}
		}
		break;

	case YAML_NO_EVENT:
		break;

	default:
		printf("@@@Unknown type\n");
		break;
	}
}

gchar* get_switch_from_header(char *header) {
	gchar* ret = NULL;
	if (g_strcmp0 ("secure_registries", header) == 0) {
		ret = " --registries ";
	}
	else if (g_strcmp0("insecure_registries", header) == 0){
		ret = " --insecure_registries ";
	}
	else if (g_strcmp0("blocked_registries", header) == 0){
		ret = " --blocked_registries ";
	}
	return ret;
}

gchar* inject_switches(gchar* command_switch, GPtrArray* values){
	gchar* ret;
	for (guint i = 0; i < values->len; i++) {
		ret = g_strconcat(g_strdup(ret), g_strdup(command_switch), g_strdup(g_ptr_array_index(values, i)), NULL);
	}
	return ret;
}

void print_final(){
	gchar *output = "";
	// Build hash lookup
	GList *keys;
	keys = g_hash_table_get_keys(hash);
	for (gint i=0; i< g_list_length(keys); i++){
		gchar* key = g_list_nth_data(keys, i);
		gchar* command_switch = get_switch_from_header(key);
		GPtrArray* values = g_hash_table_lookup(hash, key);
		//inject_switches(command_switch, values);
		gchar *value = g_strconcat(command_switch, g_strjoinv(command_switch, (gchar **) values->pdata), NULL);
		output = g_strconcat(g_strdup(output), g_strdup(value), NULL);
	}
	//Output the final string
	printf("%s\n", output);
}

int main(int argc, char *argv[])
{
	// Global vars
	hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
	tmp_values = g_ptr_array_new();

	static gboolean json = FALSE;
	//static gchar *input_file;
	char *conf_file = "docker.conf";



	static GOptionEntry entries[] =
	{
	  { "json", 'j', 0, G_OPTION_ARG_NONE, &json, "Output in JSON format", NULL },
	  //{ "input", 'i', 0, G_OPTION_ARG_STRING, &input_file, "Specific an input file", NULL },
	  { NULL }
	};

	GError *parse_error = NULL;
	GOptionContext *context;

	context = g_option_context_new ("- parses a YAML file to extract registries");
	g_option_context_add_main_entries (context, entries, NULL);
	//g_option_context_add_group (context, gtk_get_option_group (TRUE));
	if (!g_option_context_parse (context, &argc, &argv, &parse_error))
	{
	  g_print ("option parsing failed: %s\n", parse_error->message);
	  exit (1);
	}


	//if (input_file){
		//conf_file = g_strdup(input_file);
		//printf("############Here*****************");
		//conf_file = "docker.conf";
	//}
	//printf("Input_file: %s", conf_file);

	yaml_parser_t parser;
	yaml_document_t document;
	int error = 0;

	FILE *file = fopen(conf_file, "r");
	assert(file);

	assert(yaml_parser_initialize(&parser));

	yaml_parser_set_input_file(&parser, file);

	int done = 0;
	while (!done)
	{
		if (!yaml_parser_load(&parser, &document)) {
			fprintf(stderr, "Failed to load document in %s\n", conf_file);
			error = 1;
			break;
		}

		done = (!yaml_document_get_root_node(&document));

		if (!done) {
			print_yaml_node(&document, yaml_document_get_root_node(&document), FALSE);
		}

		yaml_document_delete(&document);
	}

	yaml_parser_delete(&parser);

	assert(!fclose(file));
 	print_final();
	return !error;

}
