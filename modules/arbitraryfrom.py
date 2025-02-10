def arbitraryfrom(contract):
    """
    Detects insecure usage of the transferFrom function in a smart contract.
    """
    r = re.compile(r'^.*transferFrom\(.*\).*')
    parsed_contract_into_list = parse_contract(contract)
    newlist = list(filter(r.match, parsed_contract_into_list))
    
    if not newlist:
        return None
    
    stripped = [s.strip() for s in newlist]
    r2 = re.compile(r'^.*transferFrom\(msg\.sender.*\).*')
    newlist2 = list(filter(r2.match, stripped))
    
    if not newlist2:
        newlist_to_print = [str(1 + parsed_contract_into_list.index(line)) for line in newlist]
        newlist_printable = ', '.join(newlist_to_print)
        printer_vuln(newlist_printable, vulnerability_name, vulnerability_description, vulnerability_recommendation, more_info)
        return f"Arbitrary From vulnerability found at line(s): {newlist_printable}"
    
    return None 