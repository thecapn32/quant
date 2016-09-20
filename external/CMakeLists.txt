include(externalproject)

find_program(SED sed)
externalproject_add(tommyds
  UPDATE_COMMAND ""
  GIT_REPOSITORY https://github.com/amadvance/tommyds.git
  GIT_SHALLOW 1
  PATCH_COMMAND ${SED} -i.orig -e "s/-Wpadded// $<SEMICOLON> s/-Wcast-align// \
                  $<SEMICOLON> s/objdump/echo/" Makefile
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND ${MAKE}
  INSTALL_COMMAND ""
)

externalproject_get_property(tommyds SOURCE_DIR)
add_library(tommy STATIC IMPORTED GLOBAL)
set_target_properties(tommy PROPERTIES IMPORTED_LOCATION ${SOURCE_DIR}/tommy.o)
set_target_properties(tommy
  PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${SOURCE_DIR}
)
add_dependencies(tommy tommyds)


add_custom_target(vagrant-up ${VAGRANT} up)

# location of proto-quic sources inside the VM
set(QUIC /vagrant/proto-quic-prefix/src/proto-quic)

# some convenience paths under ${QUIC}
set(QUIC_CERTS ${QUIC}/src/net/tools/quic/certs)
set(QUIC_CERTS ${QUIC_CERTS} PARENT_SCOPE)
set(QUIC_BIN ${QUIC}/src/out/Debug PARENT_SCOPE)

externalproject_add(proto-quic
  UPDATE_COMMAND ""
  EXCLUDE_FROM_ALL 1
  DEPENDS vagrant-up
  GIT_REPOSITORY https://github.com/google/proto-quic.git
  GIT_SHALLOW 1
  CONFIGURE_COMMAND ${VAGRANT} ssh -c "\
    echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula \
      select true | sudo debconf-set-selections && \
    ${QUIC}/src/build/install-build-deps.sh --no-syms --no-arm \
      --no-chromeos-fonts --no-nacl --no-prompt && \
    export PATH=$PATH:${QUIC}/depot_tools && \
    cd ${QUIC}/src && gclient runhooks && \
    cd ${QUIC_CERTS} && ./generate-certs.sh \
  "
  BUILD_IN_SOURCE 1
  BUILD_COMMAND ${VAGRANT} ssh -c "\
    export PATH=$PATH:${QUIC}/depot_tools && \
    cd ${QUIC}/src && ninja -v -C out/Debug quic_client quic_server \
  "
  INSTALL_COMMAND ""
)
