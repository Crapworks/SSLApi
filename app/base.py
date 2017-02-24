from flask import Blueprint
from flask.views import MethodView


class ApiResource(MethodView):
    """Bluebrint wrapper for MethodViews"""

    endpoint = None
    url_prefix = None
    url_rules = {}

    @classmethod
    def as_blueprint(cls, name=None):
        name = name or cls.endpoint
        blueprint = Blueprint(name, cls.__module__, url_prefix=cls.url_prefix)
        for endpoint, options in cls.url_rules.iteritems():
            url_rule = options.get('rule', '')
            defaults = options.get('defaults', {})
            blueprint.add_url_rule(url_rule, defaults=defaults, view_func=cls.as_view(endpoint))
        return blueprint
