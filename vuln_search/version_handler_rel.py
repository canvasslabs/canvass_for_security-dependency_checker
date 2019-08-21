import re
import pdb


class Version():
    def __init__(self, version_str):
        self.version_str = version_str
        self.version_numbers = self.fill_in_versions(version_str)

    def fill_in_versions(self, version_str):
        if version_str == "*":
            return "*"
        if version_str == "ALL":
            return "*"
        all_digits = re.findall("\d+", version_str)
        all_digits = [int(x) for x in all_digits]
        return all_digits

    def _handle_all(self, other):
        if self.version_str is None:
            return True
        if other is None:
            return True
        if self.version_str == "*":
            return True
        elif other.version_str == "*":
            return True
        return False

    def __eq__(self, other):
        if self._handle_all(other):
            return True
        if len(self.version_numbers) != len(other.version_numbers):
            return False
        for my_ind, my_v_num in enumerate(self.version_numbers):
            if my_v_num == other.version_numbers[my_ind]:
                pass
            else:
                return False
        return True

    def __lt__(self, other):
        if self._handle_all(other):
            return True
        other_v_count = len(other.version_numbers)
        for my_ind, my_v_num in enumerate(self.version_numbers):
            if my_ind < other_v_count:
                if my_v_num < other.version_numbers[my_ind]:
                    return True
                elif my_v_num > other.version_numbers[my_ind]:
                    return False
        return False

    def __le__(self, other):
        if self._handle_all(other):
            return True
        if other.version_numbers == "*":
            return True
        other_v_count = len(other.version_numbers)
        for my_ind, my_v_num in enumerate(self.version_numbers):
            if my_ind < other_v_count:
                if my_v_num < other.version_numbers[my_ind]:
                    return True
                elif my_v_num > other.version_numbers[my_ind]:
                    return False
        return True

    def __repr__(self):
        my_str = "Version: ".format(self.version_str)
        for my_ver_num in self.version_numbers:
            my_str += "{} ".format(my_ver_num)
        return my_str


class VersionRange():
    def __init__(self, start_eq, start_ver, end_eq, end_ver):
        self.start_eq = start_eq
        self.start_version = start_ver
        self.end_eq = end_eq
        self.end_ver = end_ver

    @classmethod
    def make_version_range(cls, my_version_str):
        my_vr = cls.parse_version(my_version_str)
        return my_vr

    @classmethod
    def parse_range(cls, my_version_str):
        if any(x in my_version_str for x in ["(", ">"]):
            start_eq = ">"
        elif any(x in my_version_str for x in ["[", ">="]):
            start_eq = ">="
        else:
            raise ValueError("No starting range such as ( or [.")
        if any(x in my_version_str for x in [")", "<"]):
            end_eq = "<"
        elif any(x in my_version_str for x in ["]", "<="]):
            end_eq = "<="
        else:
            my_error_msg = "Value Error: version string: "
            my_error_msg += "{} has no starting range such as ( or [.".format(
                my_version_str)
            raise ValueError(my_error_msg)
        return start_eq, end_eq


    @classmethod
    def parse_version(cls, my_version_str):
        start_eq, end_eq = cls.parse_range(my_version_str)

        num_entries = len(my_version_str.split(','))
        if num_entries == 2:
            my_split_str = my_version_str.split(',')
            start_version = my_split_str[0][1:]
            end_version = my_split_str[1][:-1]
            myvr = VersionRange(start_eq, Version(start_version),
                                end_eq, Version(end_version))
        elif num_entries == 1:
            start_version = my_version_str
            end_version = my_version_str
            myvr = VersionRange(start_eq, Version(start_version),
                                end_eq, Version(end_version))
        else:
            raise ValueError("Too many commas in the string {}".format(
                my_version_str))
        return myvr

    @classmethod
    def find_version_chunk(cls, mystr):
        return cls.has_two_plus_digits_separated_by_period(mystr)

    @classmethod
    def check_alphabet(cls, mystr):
        for myc in mystr:
            if myc.isalpha():
                return True
        return False

    @classmethod
    def has_both_digit_period(cls, mystr):
        hasD = hasP = False
        for myc in mystr:
            if myc.isdigit():
                hasD = True
            else:
                if myc == ".":
                    hasP = True
                else:
                    return False
        return (hasP and hasD)

    @classmethod
    def has_two_plus_digits_separated_by_period(cls, mystr):
        split_str = mystr.split(".")
        digit_sequence_count = 0
        for partial_str in split_str:
            if partial_str.isdigit():
                digit_sequence_count += 1
            else:
                digit_sequence_count = 0
            if digit_sequence_count > 1:
                return True
        return False

    def __repr__(self):
        my_str = "start_eq:{} v={} end_eq:{} end_v={}\n".format(
            self.start_eq,
            self.start_version,
            self.end_eq,
            self.end_ver)
        return my_str

    def __contains__(self, other):
        if isinstance(other, Version):
            good_start = False
            if self.start_version == Version(""):
                good_start = True
            else:
                if self.start_eq == "=":
                    return self.start_version == other
                elif self.start_eq == ">=":
                    good_start = (other >= self.start_version)
                elif self.start_eq == ">":
                    good_start = (other > self.start_version)
                elif self.start_eq is None:
                    good_start = True
                else:
                    raise ValueError("Unknown operation")
            good_end = False
            if self.end_ver == Version(""):
                good_end = True
            else:
                if self.end_eq == "=":
                    return self.end_ver == other
                elif self.end_eq == "<=":
                    good_end = (other <= self.end_ver)
                elif self.end_eq == "<":
                    good_end = (other < self.end_ver)
                elif self.end_eq is None:
                    good_end = True
            return good_start and good_end
        else:
            return False


class VersionRangeParser():
    def __init__(self):
        pass

    @classmethod
    def parse_text(cls, my_range_text):
        my_range = []
        for c in my_range_text:
            if c == "(" or c == "[":
                my_str = c
            elif c == ")" or c == "]":
                my_str += c
                myvr = VersionRange.make_version_range(my_str)
                my_range.append(myvr)
            else:
                my_str += c
        return my_range
