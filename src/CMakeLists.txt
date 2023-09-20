include (FindPkgConfig)

pkg_check_modules (SSL libssl)

add_library (creqhttp SHARED
		creqhttp.c
	)

target_include_directories (creqhttp
	PUBLIC
	${SSL_INCLUDE_DIRS}
	"../include"
	)

target_link_libraries (creqhttp
	${SSL_LIBRARIES}
	)
