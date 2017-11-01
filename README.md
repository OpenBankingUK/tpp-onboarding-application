# tpp-onboarding-application
Downloadable tool which allows creation of an SSA and onboarding with ASPSPs

## Requirements

* Needs Python 3.6.2 or greater
* `pip`

## Installation

* pull from `master`
* `pip install -r requirements.txt`

## Deployment Notes

You will ned to generate a new secret key for your application.

### Generating secret key:

`$ python -c 'import os; print os.urandom(24).encode("hex")'`

Set the `SECRET_KEY` environment variable to the value of the new key.

### Environment variables

Set `CACHE_TIMEOUT` to `3600`
Set `TEMPLATES_FOLDER` to `templates`
Set `TEST_API_ENDPOINT` to `/accounts`
Set `FLASK_DEBUG` to `True`

## Copyright

See COPYRIGHT.
