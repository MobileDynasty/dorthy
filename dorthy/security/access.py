import json

from collections import Iterable

from dorthy.json import jsonify
from dorthy.enum import DeclarativeEnum
from dorthy.utils import create_frozenset, native_str


class AccessVotes(DeclarativeEnum):

    Abstain = 1,
    Denied = 2,
    Granted = 3,


class AccessDeniedError(Exception):
    pass


class AuthorityJSONSerializer(object):

    def deserialize(self, data):
        dct = data if isinstance(data, dict) else json.loads(native_str(data))
        authority = dct["authority"]
        permission = dct.get("permission", None)
        return Authority(authority, permission)

    def serialize(self, authority):
        return jsonify(authority)


class Authority(object):
    """Authority object that represents a permission within the system.
    An authority can additionally have a permission associated
    with it to further narrow it's definition.
    """

    def __init__(self, authority, permission=None):
        self.__authority = authority
        self.__permission = permission

    def __eq__(self, other):
        if not other:
            return False
        if type(other) is not Authority:
            return False
        if self is other:
            return True
        if self.authority == other.authority and \
                self.permission == other.permission:
            return True
        return False

    def __hash__(self):
        value = hash(self.__authority)
        if self.__permission is not None:
            value = (value << 1) ^ hash(self.__permission)
        return value

    @property
    def authority(self):
        return self.__authority

    @property
    def permission(self):
        return self.__permission

    def with_permission(self, permission):
        if self.__permission:
            raise ValueError("Cannot redefine an authorities permission.")
        self.__permission = permission
        return self


def authority(auth, permission=None):
    """A helper method that provides readability to
    the authorized decorators.

    Args:
        auth: the authority which can be defined as a string or as an
        Authority object
        permission: the permission to set for the authority

    Returns:
        an AuthorityExpression with the authority set
    """
    if isinstance(auth, Authority):
        return AuthorityExpression(auth)
    elif isinstance(auth, str):
        return AuthorityExpression(Authority(auth, permission))
    else:
        raise ValueError("Invalid authority type. Only supports string and Authority.")


def member(group):
    """A helper method that provides readability to
    the authorized decorators.

    Args:
        group: the group name as a string

    Returns:
        a GroupExpression with the group set
    """
    return GroupExpression(group)


class Expression(object):

    def __and__(self, other):
        return AndExpression(self, other)

    def __or__(self, other):
        return OrExpression(self, other)

    def __neg__(self):
        return NotExpression(self)

    def apply(self, authentication, attribute, **options):
        raise NotImplementedError()


class NotExpression(Expression):

    def __init__(self, expression):
        self.expression = expression

    def apply(self, authentication, attribute, **options):
        return not self.expression.apply(authentication, attribute, **options)


class LogicExpression(Expression):

    def __init__(self, lh_expression, rh_expression):
        self.lh_expression = lh_expression
        self.rh_expression = rh_expression


class AndExpression(LogicExpression):

    def apply(self, authentication, attribute, **options):
        return self.lh_expression.apply(authentication, attribute, **options) and \
            self.rh_expression.apply(authentication, attribute, **options)


class OrExpression(LogicExpression):

    def apply(self, authentication, attribute, **options):
        return self.lh_expression.apply(authentication, attribute, **options) or \
            self.rh_expression.apply(authentication, attribute, **options)


class ValueExpression(Expression):

    def __init__(self, value):
        self.value = value


class AuthorityExpression(ValueExpression):

    def apply(self, authentication, attribute, **options):
        return self.value in authentication.get_authorities()


class GroupExpression(ValueExpression):

    def apply(self, authentication, attribute, **options):
        group_names = {g.name for g in authentication.get_groups() if g.security_group}
        return True if self.value in group_names else False


class GroupVoter(object):
    """A security group voter that votes based upon
    group membership.
    """

    def __init__(self, groups):
        """Initializes a GroupAccessVoter

        Args:
            groups (str or Iterable): the group names to check access against
        """
        self.__groups = create_frozenset(groups)

    def supports(self, expression, attribute=None):
        """Determines if voter is supported based upon the
        attribute it is tied to.

        Args:
            expression: the security expression
            attribute (object): the attribute the expression is tied to

        Returns:
            always returns True
        """
        return True

    def vote(self, authentication, expression, attribute=None, **options):
        """Votes on access rights by group membership.

        Args:
            authentication (Authentication): the authentication
            expression: the security expression
            attribute (object): the calling attribute if avaiplatle
            options: key-work options

        Returns:
            AccessVotes.Granted if the authentication contains one of the given groups
        """
        if authentication.get_groups():
            group_names = {g.name for g in authentication.get_groups() if g.security_group}
            intersect = self.__groups & group_names
            return AccessVotes.Granted if intersect else AccessVotes.Denied
        else:
            return AccessVotes.Abstain


class ExpressionVoter(object):
    """A security expression voter that processes
    a security expression and votes on access based upon
    that expression and the authority.
    """

    def __init__(self, allow_none=True):
        """
        Constructor
        :param allow_none: allows a None expression to be evaluated as Access Granted
        """
        self.allow_none = allow_none

    def supports(self, expression, attribute=None):
        """Determines if voter is supported based upon the
        attribute it is tied to.

        Args:
            expression: the security expression
            attribute (object): the attribute the expression is tied to

        Returns:
            always returns True
        """
        return True

    def vote(self, authentication,  expression, attribute=None, **options):
        """Votes on access rights by checking a principal's granted authorities
         against the security expression.

        Args:
            authentication (Authentication): the authentication
            expression: the security expression
            attribute (object): the calling attribute if avaiplatle
            options: key-work options

        Returns:
            AccessVote. AccessVotes.Granted if the authentication has been granted the
            necessary authority otherwise AccessVotes.Denied.  If the expression is
            not a security expression check expression than AccessVotes.Abstain is returned.
            If the expression is None then returns AccessVotes.Granted.
        """
        if expression is None and self.allow_none:
            return AccessVotes.Granted
        if isinstance(expression, Expression):
            if expression.apply(authentication, attribute, **options):
                return AccessVotes.Granted
            else:
                return AccessVotes.Denied
        return AccessVotes.Abstain


class BaseDecisionManager(object):

    def __init__(self, allow_all_abstain=False, cascade_authorization=True):
        self.__allow_all_abstain = allow_all_abstain
        self.__cascade_authorization = cascade_authorization

    @property
    def allow_all_abstain(self):
        return self.__allow_all_abstain

    @property
    def cascade_authorization(self):
        return self.__cascade_authorization

    def supports(self, expression, attribute=None):
        return True

    def decide(self, authentication, expression, access_history, attribute=None, **options):
        raise NotImplementedError()

    @staticmethod
    def previously_authorized(access_history):
        # first access will be contained in the access history list i.e. len = 1
        return len(access_history) > 1


class UnanimousDecisionManager(BaseDecisionManager):
    """A decision manager that requires all voters to either grant access or
    abstain -- one AccessVote.Denied will deny access for the authentication.
    """

    def __init__(self, voters, allow_all_abstain=False, cascade_authorization=True):
        """Creates a new decision manager.

        Args:
            voters: the voters used to make access decisions.  Accepts either a
            single voter or an iterable collection of voters.
        """
        assert voters, "Cannot initialize without voters."
        super().__init__(allow_all_abstain=allow_all_abstain, cascade_authorization=cascade_authorization)
        if not isinstance(voters, Iterable):
            self.__voters = [voters]
        else:
            self.__voters = voters

    def decide(self, authentication, expression, access_history, attribute=None, **options):
        """Decides whether the authentication is allowed to access the attribute given
        the security expression.

        Args:
            authentication (Authentication): the authentication
            expression: the security expression
            attribute (object): the calling attribute if avaiplatle
            access_history (list): the access history
            options: key-work options

        Raises:
            AccessDeniedError: authentication is denied access
        """
        if not self.supports(expression, attribute):
            raise AccessDeniedError()

        if not self.cascade_authorization and self.previously_authorized(access_history):
            return

        abstains = 0
        for voter in self.__voters:
            if voter.supports(expression, attribute):
                vote = voter.vote(authentication, expression, attribute=attribute, **options)
                if vote == AccessVotes.Denied:
                    raise AccessDeniedError()
                if vote == AccessVotes.Abstain:
                    abstains += 1
            else:
                abstains += 1

        # TODO: fix the iterable problem
        if not self.allow_all_abstain and abstains == len(self.__voters):
            raise AccessDeniedError()


class SuperUserDecisionManager(UnanimousDecisionManager):
    """A decision manager that grants access to a super user.
    """

    def __init__(self, super_voter, voters, allow_all_abstain=False, cascade_authorization=True):
        """Creates a new decision manager.

        Args:
            super_voter: a voter that used to make decisions about a super user
            voters: the voters used to make access decisions.  Accepts either a
            single voter or an iterable collection of voters.
        """
        assert super_voter, "Cannot initialize without a super voter."
        super().__init__(allow_all_abstain=allow_all_abstain, cascade_authorization=cascade_authorization)
        self.__super_voter = super_voter

    def decide(self, authentication, expression, access_history, attribute=None, **options):
        """Decides whether the authentication is allowed to access the attribute given
        the security expression.

        Args:
            authentication (Authentication): the authentication
            expression: the security expression
            attribute (object): the calling attribute if available
            access_history (list): the access history
            options: key-work options

        Raises:
            AccessDeniedError: authentication is denied access
        """

        # check to see if admin access is granted
        if self.__super_voter.supports(expression, attribute) and \
                self.__super_voter.vote(
                    authentication, expression, attribute=attribute, **options) == AccessVotes.Granted:
            return

        # check with the rest of the voters
        super().decide(authentication, expression, attribute=attribute, **options)

