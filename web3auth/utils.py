import sha3
import ethereum
from eth_utils import is_hex_address
from django import forms
from django.utils.translation import ugettext_lazy as _
from ethereum.utils import ecrecover_to_pub


def sig_to_vrs(sig):
    r = int(sig[2:66], 16)
    s = int(sig[66:130], 16)
    v = int(sig[130:], 16)
    return v, r, s


def hash_personal_message(msg):
    padded = "\x19Ethereum Signed Message:\n" + str(len(msg)) + msg
    return sha3.keccak_256(bytes(padded, 'utf8')).digest()


def recover_to_addr(msg, sig):
    msghash = hash_personal_message(msg)
    vrs = sig_to_vrs(sig)
    return '0x' + sha3.keccak_256(ecrecover_to_pub(msghash, *vrs)).hexdigest()[24:]


def validate_eth_address(value):
    if not is_hex_address(value):
        raise forms.ValidationError(
            _('%(value)s is not a valid Ethereum address'),
            params={'value': value},
        )


def get_redirect_url(request):
    redirect_url = request.GET.get('next') or request.POST.get('next') or settings.LOGIN_REDIRECT_URL
    try:
        url = reverse(redirect_url)
    except NoReverseMatch:
        url = redirect_url
    return url


@require_http_methods(["GET", "POST"])
def login_api(request):
    if request.method == 'GET':
        token = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(32))
        request.session['login_token'] = token
        return JsonResponse({'data': token, 'success': True})
    else:
        token = request.session.get('login_token')
        if not token:
            return JsonResponse({'error': _("No login token in session. Please request token again by sending a GET request to this URL."), 'success': False})
        else:
            form = LoginForm(token, request.POST)
            if form.is_valid():
                signature = form.cleaned_data.get("signature")
                address = form.cleaned_data.get("address")
                del request.session['login_token']
                user = authenticate(request, token=token, address=address, signature=signature)
                if user:
                    login(request, user, 'web3auth.backend.Web3Backend')
                    return JsonResponse({'success': True, 'redirect_url': get_redirect_url(request)})
                else:
                    error = _("Can't find a user for the provided signature with address {address}").format(address=address)
                    return JsonResponse({'success': False, 'error': error})
            else:
                return JsonResponse({'success': False, 'error': form.errors.get_json_data()})


@require_http_methods(["POST"])
def signup_api(request):
    if not app_settings.WEB3AUTH_SIGNUP_ENABLED:
        return JsonResponse({'success': False, 'error': _("Sorry, signups are currently disabled")})
    form = SignupForm(request.POST)
    if form.is_valid():
        user = form.save(commit=False)
        addr_field = app_settings.WEB3AUTH_USER_ADDRESS_FIELD
        setattr(user, addr_field, form.cleaned_data[addr_field])
        user.save()
        login(request, user, 'web3auth.backend.Web3Backend')
        return JsonResponse({'success': True, 'redirect_url': get_redirect_url(request)})
    else:
        return JsonResponse({'success': False, 'error': form.errors.get_json_data()})


@require_http_methods(["GET", "POST"])
def signup_view(request, template_name='web3auth/signup.html'):
    form = SignupForm()
    if not app_settings.WEB3AUTH_SIGNUP_ENABLED:
        form.add_error(None, _("Sorry, signups are currently disabled"))
    elif request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            addr_field = app_settings.WEB3AUTH_USER_ADDRESS_FIELD
            setattr(user, addr_field, form.cleaned_data[addr_field])
            user.save()
            login(request, user, 'web3auth.backend.Web3Backend')
            return redirect(get_redirect_url(request))
    return render(request, template_name, {'form': form})
