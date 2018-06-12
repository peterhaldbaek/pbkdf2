'use strict';

const expect = require('chai').expect;
const pbkdf2 = require('../pbkdf2');

it('pbkdf2 should produce hash', function () {
  expect(pbkdf2('password', 'salt', 5000, 20)).to.equal('edf738254821c55da61e6afa20efd0c657cb941c');
});
