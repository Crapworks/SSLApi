# Maintainer: Christian Eichelmann <ceichelmann@gmx.de>
pkgname=sslapi
pkgdesc="A python flask based REST api for creating/signing SSL certificates and keys"
pkgver=0.1
pkgrel=1
arch=('any')
url="https://github.com/Crapworks/SSLApi"
license=('BSD')
depends=('python' 'python-setuptools', 'python-flask', 'python-cryptography')
makedepends=('git')
conflicts=(sslapi)
provides=(sslapi)
source=("git://github.com/Crapworks/SSLApi.git#branch=master")
md5sums=(SKIP)

_repo_name=SSLApi

pkgver() {
  cd "$srcdir/$_repo_name"
  _author_ver=$(git describe | sed -e 's/-.*//' -e 's/v//')
  _last_commit_date=$(git log -1 --pretty='%cd' --date=short | tr -d '-')
  _commit_count="$(git rev-list --count HEAD)"
  echo $_author_ver.$_last_commit_date.$_commit_count
}

build() {
  cd "$srcdir/$_repo_name"

  msg "GIT checkout done or server timeout"
  msg "Starting make..."

  python3 setup.py build
}

package() {
  cd "$srcdir/$_repo_name"
  python3 setup.py install --root=$pkgdir/ --optimize=1
}
