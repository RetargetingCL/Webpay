# -*- coding: utf-'8' "-*-"
import logging
from odoo import api, models, fields
from odoo.tools import float_round, DEFAULT_SERVER_DATE_FORMAT
from odoo.tools.float_utils import float_compare, float_repr
from odoo.tools.translate import _
from base64 import b64decode
import os
import urllib2 as u2
import base64
import socket
from suds.transport import *
from suds.properties import Unskin
from urlparse import urlparse
from cookielib import CookieJar
from logging import getLogger


_logger = logging.getLogger(__name__)
try:
    from suds.client import Client
    from suds.wsse import Security
    from .wsse.suds import WssePlugin
    from suds.transport import *
    from suds.transport.https import HttpTransport
    from suds.cache import ObjectCache
    cache_path = "/tmp/{0}-suds".format(os.getuid())
    cache = ObjectCache(cache_path)
except:
    _logger.warning("No Load suds or wsse")
    pass

URLS ={
    'integ': 'https://webpay3gint.transbank.cl/WSWebpayTransaction/cxf/WSWebpayService?wsdl',
    'test': 'https://webpay3gint.transbank.cl/WSWebpayTransaction/cxf/WSWebpayService?wsdl',
    'prod': 'https://webpay3g.transbank.cl/WSWebpayTransaction/cxf/WSWebpayService?wsdl',
}

class HttpTransport(Transport):
    """
    HTTP transport using urllib2.  Provided basic http transport
    that provides for cookies, proxies but no authentication.
    """
    
    def __init__(self, **kwargs):
        """
        @param kwargs: Keyword arguments.
            - B{proxy} - An http proxy to be specified on requests.
                 The proxy is defined as {protocol:proxy,}
                    - type: I{dict}
                    - default: {}
            - B{timeout} - Set the url open timeout (seconds).
                    - type: I{float}
                    - default: 90
        """
        Transport.__init__(self)
        Unskin(self.options).update(kwargs)
        self.cookiejar = CookieJar()
        self.proxy = {}
        self.urlopener = None
        
    def open(self, request):
        try:
            url = request.url
            log.debug('opening (%s)', url)
            u2request = u2.Request(url)
            self.proxy = self.options.proxy
            return self.u2open(u2request)
        except u2.HTTPError, e:
            raise TransportError(str(e), e.code, e.fp)

    def send(self, request):
        result = None
        url = request.url
        msg = request.message
        headers = request.headers
        try:
            u2request = u2.Request(url, msg, headers)
            self.addcookies(u2request)
            self.proxy = self.options.proxy
            request.headers.update(u2request.headers)
            log.debug('sending:\n%s', request)
            fp = self.u2open(u2request)
            self.getcookies(fp, u2request)
            result = Reply(200, fp.headers.dict, fp.read())
            log.debug('received:\n%s', result)
        except u2.HTTPError, e:
            if e.code in (202,204):
                result = None
            else:
                raise TransportError(e.msg, e.code, e.fp)
        return result

    def addcookies(self, u2request):
        """
        Add cookies in the cookiejar to the request.
        @param u2request: A urllib2 request.
        @rtype: u2request: urllib2.Requet.
        """
        self.cookiejar.add_cookie_header(u2request)
        
    def getcookies(self, fp, u2request):
        """
        Add cookies in the request to the cookiejar.
        @param u2request: A urllib2 request.
        @rtype: u2request: urllib2.Requet.
        """
        self.cookiejar.extract_cookies(fp, u2request)
        
    def u2open(self, u2request):
        """
        Open a connection.
        @param u2request: A urllib2 request.
        @type u2request: urllib2.Requet.
        @return: The opened file-like urllib2 object.
        @rtype: fp
        """
        tm = self.options.timeout
        url = self.u2opener()
        if self.u2ver() < 2.6:
            socket.setdefaulttimeout(tm)
            return url.open(u2request)
        else:
            return url.open(u2request, timeout=tm)
            
    def u2opener(self):
        """
        Create a urllib opener.
        @return: An opener.
        @rtype: I{OpenerDirector}
        """
        if self.urlopener is None:
            return u2.build_opener(*self.u2handlers())
        else:
            return self.urlopener
        
    def u2handlers(self):
        """
        Get a collection of urllib handlers.
        @return: A list of handlers to be installed in the opener.
        @rtype: [Handler,...]
        """
        handlers = []
        handlers.append(u2.ProxyHandler(self.proxy))
        return handlers
            
    def u2ver(self):
        """
        Get the major/minor version of the urllib2 lib.
        @return: The urllib2 version.
        @rtype: float
        """
        try:
            part = u2.__version__.split('.', 1)
            n = float('.'.join(part))
            return n
        except Exception, e:
            log.exception(e)
            return 0
        
    def __deepcopy__(self, memo={}):
        clone = self.__class__()
        p = Unskin(self.options)
        cp = Unskin(clone.options)
        cp.update(p)
        return clone


class HttpAuthenticated(HttpTransport):
    """
    Provides basic http authentication for servers that don't follow
    the specified challenge / response model.  This implementation
    appends the I{Authorization} http header with base64 encoded
    credentials on every http request.
    """
    
    def open(self, request):
        self.addcredentials(request)
        return HttpTransport.open(self, request)
    
    def send(self, request):
        self.addcredentials(request)
        return HttpTransport.send(self, request)
    
    def addcredentials(self, request):
        credentials = self.credentials()
        if not (None in credentials):
            encoded = base64.encodestring(':'.join(credentials))
            basic = 'Basic %s' % encoded[:-1]
            request.headers['Authorization'] = basic
                 
    def credentials(self):
        return (self.options.username, self.options.password)

class PaymentAcquirerWebpay(models.Model):
    _inherit = 'payment.acquirer'

    @api.model
    def _get_providers(self,):
        providers = super(PaymentAcquirerWebpay, self)._get_providers()
        return providers

    provider = fields.Selection(
            selection_add=[('webpay', 'Webpay')]
        )
    webpay_commer_code = fields.Char(
            string="Commerce Code"
        )
    webpay_private_key = fields.Binary(
            string="User Private Key",
        )
    webpay_public_cert = fields.Binary(
            string="User Public Cert",
        )
    webpay_cert = fields.Binary(
            string='Webpay Cert',
        )
    webpay_mode = fields.Selection(
            [
                ('normal', "Normal"),
                ('mall', "Normal Mall"),
                ('oneclick', "OneClick"),
                ('completa', "Completa"),
            ],
            string="Webpay Mode",
        )
    environment = fields.Selection(
            selection_add=[('integ', 'Integración')],
        )

    @api.multi
    def _get_feature_support(self):
        res = super(PaymentAcquirerWebpay, self)._get_feature_support()
        res['fees'].append('webpay')
        return res

    @api.multi
    def webpay_compute_fees(self, amount, currency_id, country_id):
        """ Compute paypal fees.

            :param float amount: the amount to pay
            :param integer country_id: an ID of a res.country, or None. This is
                                       the customer's country, to be compared to
                                       the acquirer company country.
            :return float fees: computed fees
        """
        if not self.fees_active:
            return 0.0
        country = self.env['res.country'].browse(country_id)
        if country and self.company_id.country_id.id == country.id:
            percentage = self.fees_dom_var
            fixed = self.fees_dom_fixed
        else:
            percentage = self.fees_int_var
            fixed = self.fees_int_fixed
        fees = (percentage / 100.0 * amount + fixed) / (1 - percentage / 100.0)
        return fees

    def _get_webpay_urls(self):
        url = URLS[self.environment]
        return url

    @api.multi
    def webpay_form_generate_values(self, values):
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
        values.update({
            'business': self.company_id.name,
            'item_name': '%s: %s' % (self.company_id.name, values['reference']),
            'item_number': values['reference'],
            'amount': values['amount'],
            'currency_code': values['currency'] and values['currency'].name or '',
            'address1': values.get('partner_address'),
            'city': values.get('partner_city'),
            'country': values.get('partner_country') and values.get('partner_country').code or '',
            'state': values.get('partner_state') and (values.get('partner_state').code or values.get('partner_state').name) or '',
            'email': values.get('partner_email'),
            'zip_code': values.get('partner_zip'),
            'first_name': values.get('partner_first_name'),
            'last_name': values.get('partner_last_name'),
            'return_url': base_url + '/payment/webpay/final'
        })
        return values

    @api.multi
    def webpay_get_form_action_url(self,):
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
        return base_url + '/payment/webpay/redirect'

    def get_private_key(self):
        return b64decode(self.sudo().webpay_private_key)

    def get_public_cert(self):
        return b64decode(self.sudo().webpay_public_cert)

    def get_WebPay_cert(self):
        return b64decode(self.sudo().webpay_cert)

    def get_client(self,):
        transport = HttpTransport()
        wsse = Security()
        return Client(
            self._get_webpay_urls(),
            transport=transport,
            wsse=wsse,
            plugins=[
                WssePlugin(
                    keyfile=self.get_private_key(),
                    certfile=self.get_public_cert(),
                    their_certfile=self.get_WebPay_cert(),
                ),
            ],
            cache=cache,
        )

    """
    initTransaction

    Permite inicializar una transaccion en Webpay.
    Como respuesta a la invocacion se genera un token que representa en forma unica una transaccion.
    """
    def initTransaction(self, post):
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
        client = self.get_client()
        client.options.cache.clear()
        init = client.factory.create('wsInitTransactionInput')

        init.wSTransactionType = client.factory.create('wsTransactionType').TR_NORMAL_WS

        init.commerceId = self.webpay_commer_code

        init.buyOrder = post['item_number']
        init.sessionId = self.company_id.id
        init.returnURL = base_url + '/payment/webpay/return/'+str(self.id)
        init.finalURL = post['return_url'] + '/' + str(self.id)

        detail = client.factory.create('wsTransactionDetail')
        detail.amount = post['amount']

        detail.commerceCode = self.webpay_commer_code
        detail.buyOrder = post['item_number']

        init.transactionDetails.append(detail)
        init.wPMDetail = client.factory.create('wpmDetailInput')

        wsInitTransactionOutput = client.service.initTransaction(init)

        return wsInitTransactionOutput


class PaymentTxWebpay(models.Model):
    _inherit = 'payment.transaction'

    webpay_txn_type = fields.Selection([
            ('VD', 'Venta Debito'),
            ('VN', 'Venta Normal'),
            ('VC', 'Venta en cuotas'),
            ('SI', '3 cuotas sin interés'),
            ('S2', 'cuotas sin interés'),
            ('NC', 'N Cuotas sin interés'),
        ],
       string="Webpay Tipo Transacción")

    """
    getTransaction

    Permite obtener el resultado de la transaccion una vez que
    Webpay ha resuelto su autorizacion financiera.
    """
    @api.multi
    def getTransaction(self, acquirer_id, token):
        client = acquirer_id.get_client()
        client.options.cache.clear()
        transactionResultOutput = client.service.getTransactionResult(token)
        acknowledge = self.acknowledgeTransaction(acquirer_id, token)
        if not acknowledge:
            _logger.warning("not acknowledge %s" % acknowledge)
        else:
            _logger.warning("acknowledge")
        return transactionResultOutput

    """
    acknowledgeTransaction
    Indica  a Webpay que se ha recibido conforme el resultado de la transaccion
    """
    def acknowledgeTransaction(self, acquirer_id, token):
        client = acquirer_id.get_client()
        client.options.cache.clear()
        acknowledge = client.service.acknowledgeTransaction(token)
        return acknowledge

    @api.model
    def _webpay_form_get_tx_from_data(self, data):
        reference, txn_id = data.buyOrder, data.sessionId
        if not reference or not txn_id:
            error_msg = _('Webpay: received data with missing reference (%s) or txn_id (%s)') % (reference, txn_id)
            _logger.info(error_msg)
            raise ValidationError(error_msg)

        # find tx -> @TDENOTE use txn_id ?
        tx_ids = self.env['payment.transaction'].search([('reference', '=', reference)])
        if not tx_ids or len(tx_ids) > 1:
            error_msg = 'Webpay: received data for reference %s' % (reference)
            if not tx_ids:
                error_msg += '; no order found'
            else:
                error_msg += '; multiple order found'
            _logger.warning(error_msg)
            raise ValidationError(error_msg)
        return tx_ids[0]

    @api.multi
    def _webpay_form_validate(self, data):
        codes = {
                '0': 'Transacción aprobada.',
                '-1': 'Rechazo de transacción.',
                '-2': 'Transacción debe reintentarse.',
                '-3': 'Error en transacción.',
                '-4': 'Rechazo de transacción.',
                '-5': 'Rechazo por error de tasa.',
                '-6': 'Excede cupo máximo mensual.',
                '-7': 'Excede límite diario por transacción.',
                '-8': 'Rubro no autorizado.',
            }
        status = str(data.detailOutput[0].responseCode)
        res = {
            'acquirer_reference': data.detailOutput[0].authorizationCode,
            'webpay_txn_type': data.detailOutput[0].paymentTypeCode,
            #'date': data.transactionDate,
        }
        if status in ['0']:
            _logger.info('Validated webpay payment for tx %s: set as done' % (self.reference))
            self._set_transaction_done()
        elif status in ['-6', '-7']:
            _logger.warning('Received notification for webpay payment %s: set as pending' % (self.reference))
            self._set_transaction_pending()
        elif status in ['-1', '-4']:
            self._set_transaction_cancel()
        else:
            error = 'Received unrecognized status for webpay payment %s: %s, set as error' % (self.reference, codes[status])
            _logger.warning(error)
        return self.write(res)

    def _confirm_so(self):
        if self.state not in ['cancel']:
            return super(PaymentTxWebpay, self)._confirm_so()
        self._set_transaction_cancel()
        return True
