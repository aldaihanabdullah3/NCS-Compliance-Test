from pickle import FALSE
from bcolors import bcolors


class ncs_tls:


    def __init__(self, data):
        self.max_score = 5
        self.moderate_score = 0
        self.advanced_score = 0
        self.accepted_ciphers_tls_1_2_advanced = [
            'ECDH-ECDSA-AES256-CCM',
            'ECDH-ECDSA-AES256-CCM-8',
            'ECDHE-ECDSA-AES256-CCM',
            'ECDHE-ECDSA-AES256-CCM-8',
            ]
        self.accepted_ciphers_tls_1_2_moderate = self.accepted_ciphers_tls_1_2_advanced + [
            'ECDH-ECDSA-AES128-CCM',
            'ECDH-ECDSA-AES128-CCM-8',
            'ECDH-ECDSA-Camellia256-GCM-SHA384',
            'ECDH-ECDSA-AES256-GCM-SHA384',
            'ECDH-RSA-AES128-CCM',
            'ECDH-RSA-AES128-CCM-8',
            'ECDH-RSA-Camellia256-GCM-SHA384',
            'ECDH-RSA-AES256-GCM-SHA384',
            'ECDH-DSS-AES128-CCM',
            'ECDH-DSS-AES128-CCM-8',
            'ECDH-DSS-Camellia256-GCM-SHA384',
            'ECDH-DSS-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES128-CCM',
            'ECDHE-ECDSA-AES128-CCM-8',
            'ECDHE-ECDSA-Camellia256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-CCM',
            'ECDHE-RSA-AES128-CCM-8',
            'ECDHE-RSA-Camellia256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-DSS-AES128-CCM',
            'ECDHE-DSS-AES128-CCM-8',
            'ECDHE-DSS-Camellia256-GCM-SHA384',
            'ECDHE-DSS-AES256-GCM-SHA384',
            'DH-ECDSA-AES128-CCM',
            'DH-ECDSA-AES128-CCM-8',
            'DH-ECDSA-Camellia256-GCM-SHA384',
            'DH-ECDSA-AES256-GCM-SHA384',
            'DH-RSA-AES128-CCM',
            'DH-RSA-AES128-CCM-8',
            'DH-RSA-Camellia256-GCM-SHA384',
            'DH-RSA-AES256-GCM-SHA384',
            'DH-DSS-AES128-CCM',
            'DH-DSS-AES128-CCM-8',
            'DH-DSS-Camellia256-GCM-SHA384',
            'DH-DSS-AES256-GCM-SHA384',
            'DHE-ECDSA-AES128-CCM',
            'DHE-ECDSA-AES128-CCM-8',
            'DHE-ECDSA-Camellia256-GCM-SHA384',
            'DHE-ECDSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-CCM',
            'DHE-RSA-AES128-CCM-8',
            'DHE-RSA-Camellia256-GCM-SHA384',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-DSS-AES128-CCM',
            'DHE-DSS-AES128-CCM-8',
            'DHE-DSS-Camellia256-GCM-SHA384',
            'DHE-DSS-AES256-GCM-SHA384'
            ]
        self.accepted_ciphers_tls_1_3 = ['TLS_AES_256_GCM_SHA384']
        self.offending_ciphers_tls_1_2_moderate = list()
        self.offending_ciphers_tls_1_2_advanced = list()
        self.offending_ciphers_tls_1_3 = list()
        self.SSLv2 = False
        self.SSLv3 = False
        self.TLSv1_0 = False
        self.TLSv1_1 = False
        self.TLSv1_2 = False
        self.TLSv1_3 = False
        self.target_name = None
        self.target_ip = None
        self.target_tls_1_2_pref = list()
        self.target_tls_1_3_pref = list()
        self.target_cipher_order_status = False
        self.target_info = data["scanResult"][0]
        
        #set host name and IP
        self.set_hostname()
        #first check TLS versions
        self.check_tls_protocols()
        self.check_ciphers_order()
        self.calculate_score()
        
        #next cipher orders for TLS 1.2 and 1.3
        #all other do not check
        #decide how to score the compliance
        #compliance scoring:
        # 1 mark for each SSL/TLS version
        # if the version does not comply with the standard then you lose the mark
        # for tls 1.2 & 1.3
        # cipher order must be enabled
        # then check all ciphers in the order
        # if one of the ciphers is not in the standard then stop and you lose the mark


    def __repr__(self):
        text = bcolors.HEADER + "==============START==============" + bcolors.ENDC + "\n"
        text += "Host Name : "+ self.target_name + "\n"
        text += "IP address : "+ self.target_ip + "\n"
        text += "SSLv2 : " + bcolors.color_bool(self.SSLv2, False) + "\n"
        text += "SSLv3 : " + bcolors.color_bool(self.SSLv3, False) + "\n"
        text += "TLS 1.0 : " + bcolors.color_bool(self.TLSv1_0, False) + "\n"
        text += "TLS 1.1 : " + bcolors.color_bool(self.TLSv1_1, False) + "\n"
        text += "TLS 1.2 : " + bcolors.color_bool(self.TLSv1_2, True) + "\n"
        text += "TLS 1.3 : " + bcolors.color_bool(self.TLSv1_3, True) + "\n"
        
        if self.target_cipher_order_status == False:
            text += bcolors.FAIL + "Cipher Order is Not Enabled!" + bcolors.ENDC + "\n" 
        else:
            if self.TLSv1_2:
                    if len(self.offending_ciphers_tls_1_2_moderate) > 0:
                        text += "\n"
                        text += "Offending ciphers for TLS 1.2 Moderate Level: " + bcolors.FAIL + str(self.offending_ciphers_tls_1_2_moderate) + bcolors.ENDC + "\n"
                        text += "\n"
                    if len(self.offending_ciphers_tls_1_2_advanced) > 0:
                        text += "\n"
                        text += "Offending ciphers for TLS 1.2 Advanced Level: " + bcolors.FAIL + str(self.offending_ciphers_tls_1_2_advanced) + bcolors.ENDC + "\n"
                        text += "\n"

            if self.TLSv1_3 and len(self.offending_ciphers_tls_1_3):
                text += "\n"
                text += "Offending ciphers for TLS 1.3: " + bcolors.FAIL + str(self.offending_ciphers_tls_1_3) + bcolors.ENDC + "\n"
                text += "\n"

        text += "Moderate Score = " + bcolors.color_scores((self.moderate_score / self.max_score) * 100) + "\n"
        text += "Advanced Score = " + bcolors.color_scores((self.advanced_score / self.max_score) * 100) + "\n"
        text += bcolors.HEADER + "===============END===============" + bcolors.ENDC
        return text


    def set_hostname(self):
        self.target_name = self.target_info["targetHost"]
        self.target_ip = self.target_info["ip"]


    def check_tls_version_value(self, data):
        if 'not offered' in data['finding']:
            return False
        else:
            return True


    def check_tls_protocols(self):
        for i in self.target_info["protocols"]:
            p = i["id"]
            if p ==  "SSLv2":
                self.SSLv2 = self.check_tls_version_value(i)
            elif p == "SSLv3":
                self.SSLv3 = self.check_tls_version_value(i) 
            elif p == "TLS1":
                self.TLSv1_0 = self.check_tls_version_value(i)
            elif p == "TLS1_1":
                self.TLSv1_1 = self.check_tls_version_value(i)
            elif p == "TLS1_2":
                self.TLSv1_2 = self.check_tls_version_value(i)
            elif p == "TLS1_3":
                self.TLSv1_3 = self.check_tls_version_value(i)


    def check_ciphers_list(self, target_list, accepted_list):
        compliance_list = list()
        for i in target_list:
            for j in accepted_list:
                if i == j:
                    compliance_list.append(i)
                    break
        
        return list(set(target_list) - set(compliance_list))

    def check_ciphers_order(self):
        for i in self.target_info["serverPreferences"]:
            if i["id"] == "cipher_order":
                if i["severity"] == "OK":
                    self.target_cipher_order_status = True
            if self.TLSv1_2 == True:
                if i["id"] == "cipherorder_TLSv1_2":
                    self.target_tls_1_2_pref = i["finding"].split()
                    self.offending_ciphers_tls_1_2_moderate = self.check_ciphers_list(
                        self.target_tls_1_2_pref, 
                        self.accepted_ciphers_tls_1_2_moderate)
                    self.offending_ciphers_tls_1_2_advanced = self.check_ciphers_list(
                        self.target_tls_1_2_pref, 
                        self.accepted_ciphers_tls_1_2_advanced)
                    continue
            
            if self.TLSv1_3 == True:
                if i["id"] == "cipherorder_TLSv1_3":
                    self.target_tls_1_3_pref = i["finding"].split()
                    self.offending_ciphers_tls_1_3 = self.check_ciphers_list(
                        self.target_tls_1_3_pref, 
                        self.accepted_ciphers_tls_1_3)
                    continue
    

    def calculate_score(self):
        # corner case to consider
        # if TLSv1.2 is disabled and TLSv1.3 is enabled then TLSv1.2 score is considered correct
        # vice versa is correct
        
        if self.SSLv2 == False:
            self.moderate_score += 1
            self.advanced_score += 1

        if self.SSLv3 == False:
            self.moderate_score += 1
            self.advanced_score += 1
        
        if self.TLSv1_0 == False:
            self.moderate_score += 1
            self.advanced_score += 1
        
        if self.TLSv1_1 == False:
            self.moderate_score += 1
            self.advanced_score += 1

        if self.TLSv1_2 == False:
            self.moderate_score += 1
            self.advanced_score += 1
        #only calculate score for version if cipher order is enabled
        elif self.target_cipher_order_status:
            comb_len_mod = len(self.target_tls_1_2_pref) - len(self.offending_ciphers_tls_1_2_moderate)
            comb_len_adv = len(self.target_tls_1_2_pref) - len(self.offending_ciphers_tls_1_2_advanced)
            if comb_len_mod != 0:
                self.moderate_score += comb_len_mod / len(self.target_tls_1_2_pref)

            if comb_len_adv != 0:    
                self.advanced_score += comb_len_adv / len(self.target_tls_1_2_pref)
            
        if self.TLSv1_3 == True:
            self.max_score += 1
            if self.target_cipher_order_status:
                comb_len = len(self.target_tls_1_3_pref) - len(self.offending_ciphers_tls_1_3)
                if comb_len != 0:
                    self.moderate_score += comb_len / len(self.target_tls_1_3_pref)
                    self.advanced_score += comb_len / len(self.target_tls_1_3_pref)