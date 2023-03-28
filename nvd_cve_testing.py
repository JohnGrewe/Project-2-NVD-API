from nvd_cve_analysis import *


if __name__ =="__main__":
    year = 2022
    month = 2
    response = request_cve_list(year, month)

    json_response = response.json()

    print(response)
    print(type(json_response))
    print(json_response)

    