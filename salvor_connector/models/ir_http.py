from werkzeug.exceptions import RequestEntityTooLarge

from odoo import models
from odoo.http import request


class IrHttp(models.AbstractModel):
    _inherit = "ir.http"

    @classmethod
    def _pre_dispatch(cls, rule, args):
        """Enforce the body limit the Salvor routes declare (``max_content_length``)
        before Odoo parses a form or multipart body and before the token check.

        - A declared Content-Length over the limit: 413.
        - A chunked body (Transfer-Encoding: chunked, or a server that marks the
          input as terminated), with or without a Content-Length: 413. werkzeug does not cap
          such a stream with ``max_content_length``, and these routes only take
          small bodies, which Salvor always sends with a Content-Length.
        - Otherwise the limit is set on the werkzeug request itself (Odoo 16 has
          no route option for it; on 17+ Odoo sets the same value).
        """
        limit = rule.endpoint.routing.get("max_content_length")
        if limit and isinstance(limit, int) and rule.endpoint.routing.get("routes", [""])[0].startswith("/salvor/"):
            httprequest = request.httprequest
            environ = httprequest.environ
            # chunked is refused whatever Content-Length says (a request may carry both)
            chunked = "chunked" in (environ.get("HTTP_TRANSFER_ENCODING") or "").lower()
            if chunked or environ.get("wsgi.input_terminated"):
                raise RequestEntityTooLarge()
            length = httprequest.content_length
            if length is not None and length > limit:
                raise RequestEntityTooLarge()
            wrapped = getattr(httprequest, "_HTTPRequest__wrapped", None)
            if wrapped is not None:
                wrapped.max_content_length = limit
        super()._pre_dispatch(rule, args)
