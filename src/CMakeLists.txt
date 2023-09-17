include (FindPkgConfig)

pkg_check_modules (SSL libssl)

add_library (creqhttp
		creqhttp.c
	)

target_include_directories (creqhttp
	PUBLIC
	${SSL_INCLUDE_DIRS}
	)

target_link_libraries (creqhttp
	${SSL_LIBRARIES}
	)

set (EXECUTABLE_OUTPUT_PATH ..)
