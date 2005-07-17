
XMLFILES= api/file/sc_list_files.xml api/file/sc_write_binary.xml \
	api/file/sc_delete_file.xml api/file/chapter.xml \
	api/file/sc_create_file.xml api/file/sc_append_record.xml \
	api/file/sc_read_record.xml api/file/sc_select_file.xml \
	api/file/sc_read_binary.xml api/file/sc_update_record.xml \
	api/file/sc_file_free.xml api/file/sc_update_binary.xml \
	api/file/sc_file_dup.xml api/file/sc_write_record.xml \
	api/file/sc_file_new.xml api/file/sc_delete_record.xml \
	api/asn1/sc_format_asn1_entry.xml api/asn1/sc_asn1_print_tags.xml \
	api/asn1/sc_asn1_find_tag.xml api/asn1/sc_copy_asn1_entry.xml \
	api/asn1/sc_asn1_encode.xml api/asn1/chapter.xml \
	api/asn1/sc_asn1_verify_tag.xml api/asn1/sc_asn1_skip_tag.xml \
	api/asn1/sc_asn1_decode.xml api/asn1/sc_asn1_put_tag.xml \
	api/asn1/sc_asn1_read_tag.xml api/apps/sc_update_dir.xml \
	api/apps/chapter.xml api/apps/sc_free_apps.xml \
	api/apps/sc_find_pkcs15_app.xml api/apps/sc_enum_apps.xml \
	api/apps/sc_find_app_by_aid.xml api/init/sc_make_cache_dir.xml \
	api/init/sc_get_cache_dir.xml api/init/chapter.xml \
	api/init/sc_establish_context.xml api/init/sc_release_context.xml \
	api/init/sc_card_valid.xml api/init/sc_set_card_driver.xml \
	api/init/sc_connect_card.xml api/init/sc_disconnect_card.xml \
	api/init/sc_detect_card_presence.xml api/types/sc_card_t.xml \
	api/types/sc_path_t.xml api/types/chapter.xml \
	api/types/sc_file_t.xml api/types/sc_asn1_entry.xml \
	api/types/sc_app_info_t.xml api/card/sc_unlock.xml \
	api/card/chapter.xml api/card/sc_format_apdu.xml \
	api/card/sc_get_challenge.xml api/card/sc_put_data.xml \
	api/card/sc_check_sw.xml api/card/sc_get_data.xml \
	api/card/sc_lock.xml api/card/sc_transmit_apdu.xml \
	api/card/sc_card_ctl.xml api/card/sc_wait_for_event.xml \
	api/misc/chapter.xml api/util/sc_der_clear.xml \
	api/util/chapter.xml api/util/sc_base64_encode.xml \
	api/util/sc_strerror.xml api/util/sc_der_copy.xml \
	api/util/sc_base64_decode.xml api/api.xml

EXTRA_DIST = $(XMLFILES) api/api.css api/man.xsl api/html.xsl

XSLTPROC = xsltproc --xinclude

html:
	$(XSLTPROC) -o html/api.html api/html.xsl api/api.xml

man:
	$(XSLTPROC) -o man/ api/man.xsl api/api.xml
