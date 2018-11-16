from django import forms

class MetaDefenderConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    url = forms.CharField(required=True,
                          label="Metadefender URL",
                          widget=forms.TextInput(),
                          initial='',
                          help_text="Example: https://metadefender.localhost:8008")
    use_proxy = forms.BooleanField(required=False,
                                   label="Proxy",
                                   initial=False,
                                   help_text="Use proxy for connecting to MetaDefender service")
    #added api key for metadefender
    api_key = forms.CharField(required=True,
                          label="Metadefender API Key",
                          widget=forms.TextInput(),
                          initial='',
                          help_text="Example: "
                                    "aaa1111bbb222ccc333f")
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(MetaDefenderConfigForm, self).__init__(*args, **kwargs)

