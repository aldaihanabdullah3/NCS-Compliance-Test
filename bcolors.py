from logging import WARNING


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def color_scores(score):
        if score < 50:
            return bcolors.FAIL + str(score) + bcolors.ENDC
        elif score < 100:
            return bcolors.WARNING + str(score) + bcolors.ENDC
        else:
            return bcolors.OKGREEN + str(score) + bcolors.ENDC
    

    def color_bool(bool_status, green_status):
        if bool_status == green_status:
            return bcolors.OKGREEN + str(bool_status) + bcolors.ENDC
        else:
            return bcolors.FAIL + str(bool_status) + bcolors.ENDC
