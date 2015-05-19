project "bnet"
	uuid "e72d44a0-ab28-11e0-9f1c-0800200c9a66"
	kind "StaticLib"

	includedirs {
		BX_DIR .. "include",
		BNET_DIR .. "include",
	}

	configuration "Debug"
		defines {
			"BNET_CONFIG_DEBUG=1",
		}

	configuration {}

	files {
		BNET_DIR .. "include/**.h",
		BNET_DIR .. "src/**.cpp",
		BNET_DIR .. "src/**.h",
	}

	copyLib()
