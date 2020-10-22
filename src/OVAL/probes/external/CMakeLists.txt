if(OPENSCAP_PROBE_EXTERNAL_DEFAULT)
	list(APPEND EXTERNAL_PROBES_SOURCES
		"default_probe.c"
		"default_probe.h"
	)
endif()

if(EXTERNAL_PROBES_SOURCES)
	add_library(external_probes_object OBJECT ${EXTERNAL_PROBES_SOURCES})
	set_oscap_generic_properties(external_probes_object)
	target_include_directories(external_probes_object PRIVATE ${EXTERNAL_PROBES_INCLUDE_DIRECTORIES})
endif()
