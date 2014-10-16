from os import path

from jinja2 import Environment, FileSystemLoader

__template_environments = dict()


def get_template(template_path, template_name, parent=None):
    template_env = get_environment(template_path)
    return template_env.get_template(template_name, parent=parent)


def get_environment(template_path):
    if template_path not in __template_environments:
        raise LookupError("Template environment not configured.")
    return __template_environments[template_path]


def config_environment(template_path,
                       block_start_string="{%",
                       block_end_string="%}",
                       variable_start_string="{{",
                       variable_end_string="}}",
                       comment_start_string="{#",
                       comment_end_string="#}",
                       extensions=None,
                       auto_escape=True,
                       cache_size=-1,
                       auto_reload=True,
                       global_vars=None):

    def _auto_escape(template_name):
        if template_name is None or "." not in template_name:
            return False
        ext = template_name.rsplit(".", 1)[1]
        return ext in ("html", "htm", "xml")

    if template_path in __template_environments:
        return

    abspath = path.abspath(template_path)
    loader = FileSystemLoader(abspath)

    if auto_escape:
        if extensions is not None:
            exts = list(extensions)
            exts.append("jinja2.ext.autoescape")
        else:
            exts = ["jinja2.ext.autoescape"]

        env = Environment(autoescape=_auto_escape,
                          block_start_string=block_start_string,
                          block_end_string=block_end_string,
                          variable_start_string=variable_start_string,
                          variable_end_string=variable_end_string,
                          comment_start_string=comment_start_string,
                          comment_end_string=comment_end_string,
                          extensions=exts,
                          cache_size=cache_size,
                          auto_reload=auto_reload,
                          loader=loader)
    else:
        env = Environment(block_start_string=block_start_string,
                          block_end_string=block_end_string,
                          variable_start_string=variable_start_string,
                          variable_end_string=variable_end_string,
                          comment_start_string=comment_start_string,
                          comment_end_string=comment_end_string,
                          extensions=extensions,
                          cache_size=cache_size,
                          auto_reload=auto_reload,
                          loader=loader)

    if global_vars:
        env.globals.update(global_vars)

    __template_environments[template_path] = env


def render(template_path, template_name, parent=None, **kwargs):
    template = get_template(template_path, template_name, parent=parent)
    return template.render(**kwargs)
