        #include <cmrc/cmrc.hpp>
#include <map>
#include <utility>

namespace cmrc {
namespace vio {

namespace res_chars {
// These are the files which are available in this resource library
// Pointers to default_certs/cert.pem
extern const char* const f_5fd8_default_certs_cert_pem_begin;
extern const char* const f_5fd8_default_certs_cert_pem_end;
}

namespace {

const cmrc::detail::index_type&
get_root_index() {
    static cmrc::detail::directory root_directory_;
    static cmrc::detail::file_or_directory root_directory_fod{root_directory_};
    static cmrc::detail::index_type root_index;
    root_index.emplace("", &root_directory_fod);
    struct dir_inl {
        class cmrc::detail::directory& directory;
    };
    dir_inl root_directory_dir{root_directory_};
    (void)root_directory_dir;
    static auto f_c9ad_default_certs_dir = root_directory_dir.directory.add_subdir("default_certs");
    root_index.emplace("default_certs", &f_c9ad_default_certs_dir.index_entry);
    root_index.emplace(
        "default_certs/cert.pem",
        f_c9ad_default_certs_dir.directory.add_file(
            "cert.pem",
            res_chars::f_5fd8_default_certs_cert_pem_begin,
            res_chars::f_5fd8_default_certs_cert_pem_end
        )
    );
    return root_index;
}

}

cmrc::embedded_filesystem get_filesystem() {
    static auto& index = get_root_index();
    return cmrc::embedded_filesystem{index};
}

} // vio
} // cmrc
    