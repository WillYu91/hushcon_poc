cmake_minimum_required(VERSION 2.6.2)
get_filename_component(THIS_PROJECT_NAME "${CMAKE_CURRENT_SOURCE_DIR}" NAME)

set (CMAKE_CXX_STANDARD 14)

# Add in this project's files
FILE(GLOB SOURCE_FILES "*.cpp")
FILE(GLOB HEADER_FILES "*.h")

add_executable (${THIS_PROJECT_NAME}
	        	${HEADER_FILES}
        		${SOURCE_FILES})