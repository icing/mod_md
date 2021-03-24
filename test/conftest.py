from TestEnv import TestEnv


def pytest_report_header(config, startdir):
    TestEnv.init()
    return "mod_md: {version} [apache: {aversion}({prefix}), mod_{ssl}]".format(
        version=TestEnv.A2MD_VERSION,
        prefix=TestEnv.PREFIX,
        aversion=TestEnv.get_httpd_version(),
        ssl=TestEnv.get_ssl_module(),
    )