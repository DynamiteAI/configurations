# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1/build

# Utility rule file for bif-plugin-Corelight_CommunityID-communityid.bif.

# Include the progress variables for this target.
include CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif.dir/progress.make

CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif: communityid.bif.h
CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif: communityid.bif.cc
CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif: communityid.bif.init.cc
CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif: communityid.bif.register.cc


communityid.bif.h: ../src/communityid.bif
communityid.bif.h: /tmp/dynamite/install_cache/zeek-4.0.3/build/auxil/bifcl/bifcl
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[BIFCL] Processing src/communityid.bif"
	/tmp/dynamite/install_cache/zeek-4.0.3/build/auxil/bifcl/bifcl -p Corelight::CommunityID /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1/src/communityid.bif || ( rm -f communityid.bif.h communityid.bif.cc communityid.bif.init.cc communityid.bif.register.cc && exit 1 )
	/usr/bin/cmake -E copy communityid.bif.zeek /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1/build/lib/bif/communityid.bif.zeek
	/usr/bin/cmake -E remove -f communityid.bif.zeek

communityid.bif.cc: communityid.bif.h
	@$(CMAKE_COMMAND) -E touch_nocreate communityid.bif.cc

communityid.bif.init.cc: communityid.bif.h
	@$(CMAKE_COMMAND) -E touch_nocreate communityid.bif.init.cc

communityid.bif.register.cc: communityid.bif.h
	@$(CMAKE_COMMAND) -E touch_nocreate communityid.bif.register.cc

lib/bif/communityid.bif.zeek: communityid.bif.h
	@$(CMAKE_COMMAND) -E touch_nocreate lib/bif/communityid.bif.zeek

bif-plugin-Corelight_CommunityID-communityid.bif: CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif
bif-plugin-Corelight_CommunityID-communityid.bif: communityid.bif.h
bif-plugin-Corelight_CommunityID-communityid.bif: communityid.bif.cc
bif-plugin-Corelight_CommunityID-communityid.bif: communityid.bif.init.cc
bif-plugin-Corelight_CommunityID-communityid.bif: communityid.bif.register.cc
bif-plugin-Corelight_CommunityID-communityid.bif: lib/bif/communityid.bif.zeek
bif-plugin-Corelight_CommunityID-communityid.bif: CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif.dir/build.make

.PHONY : bif-plugin-Corelight_CommunityID-communityid.bif

# Rule to build all files generated by this target.
CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif.dir/build: bif-plugin-Corelight_CommunityID-communityid.bif

.PHONY : CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif.dir/build

CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif.dir/clean

CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif.dir/depend:
	cd /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1 /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1 /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1/build /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1/build /tmp/dynamite/install_cache/configurations/base/default_configs/zeek/uncompiled_scripts/zeek-community-id-3.2.1/build/CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bif-plugin-Corelight_CommunityID-communityid.bif.dir/depend
