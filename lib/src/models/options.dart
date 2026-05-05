import 'package:collection/collection.dart';

final class RelyingPartyEntity {
  final String name;
  final String? id;

  const RelyingPartyEntity({required this.name, this.id});

  Map<String, dynamic> toJson() {
    return {'name': name, if (id != null) 'id': id};
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is RelyingPartyEntity &&
          runtimeType == other.runtimeType &&
          name == other.name &&
          id == other.id;

  @override
  int get hashCode => name.hashCode ^ id.hashCode;
}

final class UserEntity {
  final String id;
  final String name;
  final String displayName;

  const UserEntity({
    required this.id,
    required this.name,
    required this.displayName,
  });

  Map<String, dynamic> toJson() {
    return {'id': id, 'name': name, 'displayName': displayName};
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is UserEntity &&
          runtimeType == other.runtimeType &&
          id == other.id &&
          name == other.name &&
          displayName == other.displayName;

  @override
  int get hashCode => id.hashCode ^ name.hashCode ^ displayName.hashCode;
}

final class PubKeyCredParam {
  final String type;
  final int alg;

  const PubKeyCredParam({this.type = 'public-key', required this.alg});

  Map<String, dynamic> toJson() {
    return {'type': type, 'alg': alg};
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PubKeyCredParam &&
          runtimeType == other.runtimeType &&
          type == other.type &&
          alg == other.alg;

  @override
  int get hashCode => type.hashCode ^ alg.hashCode;
}

final class AuthenticatorSelectionCriteria {
  final String? authenticatorAttachment;
  final bool? requireResidentKey;
  final String? residentKey;
  final String? userVerification;

  const AuthenticatorSelectionCriteria({
    this.authenticatorAttachment,
    this.requireResidentKey,
    this.residentKey,
    this.userVerification,
  });

  Map<String, dynamic> toJson() {
    return {
      if (authenticatorAttachment != null)
        'authenticatorAttachment': authenticatorAttachment,
      if (requireResidentKey != null) 'requireResidentKey': requireResidentKey,
      if (residentKey != null) 'residentKey': residentKey,
      if (userVerification != null) 'userVerification': userVerification,
    };
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is AuthenticatorSelectionCriteria &&
          runtimeType == other.runtimeType &&
          authenticatorAttachment == other.authenticatorAttachment &&
          requireResidentKey == other.requireResidentKey &&
          residentKey == other.residentKey &&
          userVerification == other.userVerification;

  @override
  int get hashCode =>
      authenticatorAttachment.hashCode ^
      requireResidentKey.hashCode ^
      residentKey.hashCode ^
      userVerification.hashCode;
}

final class PublicKeyCredentialCreationOptions {
  final RelyingPartyEntity rp;
  final UserEntity user;
  final String challenge;
  final List<PubKeyCredParam> pubKeyCredParams;
  final int? timeout;
  final List<String>? excludeCredentials;
  final AuthenticatorSelectionCriteria? authenticatorSelection;
  final String? attestation;
  final Map<String, dynamic>? extensions;

  const PublicKeyCredentialCreationOptions({
    required this.rp,
    required this.user,
    required this.challenge,
    required this.pubKeyCredParams,
    this.timeout,
    this.excludeCredentials,
    this.authenticatorSelection,
    this.attestation,
    this.extensions,
  });

  Map<String, dynamic> toJson() {
    return {
      'rp': rp.toJson(),
      'user': user.toJson(),
      'challenge': challenge,
      'pubKeyCredParams': pubKeyCredParams.map((e) => e.toJson()).toList(),
      if (timeout != null) 'timeout': timeout,
      if (excludeCredentials != null) 'excludeCredentials': excludeCredentials,
      if (authenticatorSelection != null)
        'authenticatorSelection': authenticatorSelection!.toJson(),
      if (attestation != null) 'attestation': attestation,
      if (extensions != null) 'extensions': extensions,
    };
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PublicKeyCredentialCreationOptions &&
          runtimeType == other.runtimeType &&
          rp == other.rp &&
          user == other.user &&
          challenge == other.challenge &&
          const ListEquality().equals(
            pubKeyCredParams,
            other.pubKeyCredParams,
          ) &&
          timeout == other.timeout &&
          const ListEquality().equals(
            excludeCredentials,
            other.excludeCredentials,
          ) &&
          authenticatorSelection == other.authenticatorSelection &&
          attestation == other.attestation &&
          const MapEquality().equals(extensions, other.extensions);

  @override
  int get hashCode =>
      rp.hashCode ^
      user.hashCode ^
      challenge.hashCode ^
      const ListEquality().hash(pubKeyCredParams) ^
      timeout.hashCode ^
      const ListEquality().hash(excludeCredentials) ^
      authenticatorSelection.hashCode ^
      attestation.hashCode ^
      const MapEquality().hash(extensions);
}

final class PublicKeyCredentialDescriptor {
  final String type;
  final String id;
  final List<String>? transports;

  const PublicKeyCredentialDescriptor({
    this.type = 'public-key',
    required this.id,
    this.transports,
  });

  Map<String, dynamic> toJson() {
    return {
      'type': type,
      'id': id,
      if (transports != null) 'transports': transports,
    };
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PublicKeyCredentialDescriptor &&
          runtimeType == other.runtimeType &&
          type == other.type &&
          id == other.id &&
          const ListEquality().equals(transports, other.transports);

  @override
  int get hashCode =>
      type.hashCode ^ id.hashCode ^ const ListEquality().hash(transports);
}

final class PublicKeyCredentialRequestOptions {
  final String challenge;
  final int? timeout;
  final String? rpId;
  final List<PublicKeyCredentialDescriptor>? allowCredentials;
  final String? userVerification;
  final Map<String, dynamic>? extensions;

  const PublicKeyCredentialRequestOptions({
    required this.challenge,
    this.timeout,
    this.rpId,
    this.allowCredentials,
    this.userVerification,
    this.extensions,
  });

  Map<String, dynamic> toJson() {
    return {
      'challenge': challenge,
      if (timeout != null) 'timeout': timeout,
      if (rpId != null) 'rpId': rpId,
      if (allowCredentials != null)
        'allowCredentials': allowCredentials!.map((e) => e.toJson()).toList(),
      if (userVerification != null) 'userVerification': userVerification,
      if (extensions != null) 'extensions': extensions,
    };
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PublicKeyCredentialRequestOptions &&
          runtimeType == other.runtimeType &&
          challenge == other.challenge &&
          timeout == other.timeout &&
          rpId == other.rpId &&
          const ListEquality().equals(
            allowCredentials,
            other.allowCredentials,
          ) &&
          userVerification == other.userVerification &&
          const MapEquality().equals(extensions, other.extensions);

  @override
  int get hashCode =>
      challenge.hashCode ^
      timeout.hashCode ^
      rpId.hashCode ^
      const ListEquality().hash(allowCredentials) ^
      userVerification.hashCode ^
      const MapEquality().hash(extensions);
}
