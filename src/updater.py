import json
import asyncio
import asyncpg
from datetime import datetime
import cpe as cpe_module

POSTGRES = {
    "user": "postgres",
    "password": "password",
    "database": "updater_db",
    "host": "127.0.0.1"
}


#

def filter_cpe_string(element):
    result = {
        "component": None,
        "version": None
    }

    try:
        c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_2)
    except ValueError as value_error:
        try:
            c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_3)
        except ValueError as another_value_error:
            try:
                c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_UNDEFINED)
            except NotImplementedError as not_implemented_error:
                c22 = None

    c22_product = c22.get_product() if c22 is not None else []
    c22_version = c22.get_version() if c22 is not None else []
    result["component"] = c22_product[0] if isinstance(c22_product, list) and len(c22_product) > 0 else None
    result["version"] = c22_version[0] if isinstance(c22_version, list) and len(c22_version) > 0 else None

    return result

#

async def drop_table_vulnerabilities():
    connection = await asyncpg.connect(
        user=POSTGRES["user"],
        password=POSTGRES["password"],
        database=POSTGRES["database"],
        host=POSTGRES["host"]
    )
    values = await connection.fetch(
        '''
        DROP TABLE IF EXISTS vulnerabilities;
        '''
    )
    await connection.close()

async def create_table_vulnerabilities():
    connection = await asyncpg.connect(
        user=POSTGRES["user"],
        password=POSTGRES["password"],
        database=POSTGRES["database"],
        host=POSTGRES["host"]
    )
    values = await connection.fetch(
        '''
        CREATE TABLE vulnerabilities(
            id INTEGER PRIMARY KEY,
            component TEXT,
            version TEXT,
            cve TEXT,
            cwe TEXT[],
            cpe TEXT[],
            capec TEXT[],
            data_format TEXT,
            data_type TEXT,
            data_version TEXT,
            published TIMESTAMP,
            last_modified TIMESTAMP,
            description TEXT,
            refs TEXT[],
            vendors TEXT[],
            cvssv2_access_complexity TEXT,
            cvssv2_access_vector TEXT,
            cvssv2_authentication TEXT,
            cvssv2_availability_impact TEXT,
            cvssv2_base_score TEXT,
            cvssv2_confidentiality_impact TEXT,
            cvssv2_exploitability_score TEXT,
            cvssv2_impact_score TEXT,
            cvssv2_integrity_impact TEXT,
            cvssv2_obtain_all_privilege TEXT,
            cvssv2_obtain_other_privilege TEXT,
            cvssv2_obtain_user_privilege TEXT,
            cvssv2_severity TEXT,
            cvssv2_user_interaction_required TEXT,
            cvssv2_vector_string TEXT,
            cvssv2_version TEXT,
            cvssv3_attack_complexity TEXT,
            cvssv3_attack_vector TEXT,
            cvssv3_availability_impact TEXT,
            cvssv3_base_score TEXT,
            cvssv3_base_severity TEXT,
            cvssv3_confidentiality_impact TEXT,
            cvssv3_exploitability_score TEXT,
            cvssv3_impact_score TEXT,
            cvssv3_integrity_impact TEXT,
            cvssv3_privileges_required TEXT,
            cvssv3_scope TEXT,
            cvssv3_user_interaction TEXT,
            cvssv3_vector_string TEXT,
            cvssv3_version TEXT
        );
        '''
    )
    await connection.close()

async def get_all_rows_from_table_cve():
    connection = await asyncpg.connect(
        user=POSTGRES["user"],
        password=POSTGRES["password"],
        database=POSTGRES["database"],
        host=POSTGRES["host"]
    )
    values = await connection.fetch(
        '''
        SELECT * FROM cve_vulners;
        '''
    )
    await connection.close()
    return list(values)

async def fill_table_vulnerabilities(cve_list):
    connection = await asyncpg.connect(
        user=POSTGRES["user"],
        password=POSTGRES["password"],
        database=POSTGRES["database"],
        host=POSTGRES["host"]
    )
    for cve_item in cve_list:
        cpe_strings = list(cve_item["cpe22"])
        for cpe_element_in_cpes22_string in cpe_strings:
            cpe_parsed_element = filter_cpe_string(cpe_element_in_cpes22_string)
            component = cpe_parsed_element["component"]
            version = cpe_parsed_element["version"]
            print('Process CPE: {}::{}'.format(component, version))
            values = await connection.fetch(
                '''
                SELECT * FROM vulnerabilities WHERE component='{}' AND version='{}';
                '''.format(
                    component,
                    version
                )
            )
            values_list = list(values)
            if len(values_list) == 0:
                pass
            else:
                pass
    await connection.close()



loop = asyncio.get_event_loop()

loop.run_until_complete(
    drop_table_vulnerabilities()
)
loop.run_until_complete(
    create_table_vulnerabilities()
)

cve_list = loop.run_until_complete(
    get_all_rows_from_table_cve()
)

print(len(cve_list))

print(
    loop.run_until_complete(
        fill_table_vulnerabilities(cve_list=cve_list[:10])
    )
)