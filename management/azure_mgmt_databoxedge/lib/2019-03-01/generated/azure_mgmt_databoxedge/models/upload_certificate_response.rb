# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_03_01
  module Models
    #
    # The upload registration certificate response.
    #
    class UploadCertificateResponse

      include MsRestAzure

      # @return [AuthenticationType] Specifies authentication type. Possible
      # values include: 'Invalid', 'AzureActiveDirectory'
      attr_accessor :auth_type

      # @return [String] The resource ID of the Data Box Edge/Gateway device.
      attr_accessor :resource_id

      # @return [String] Azure Active Directory tenant authority.
      attr_accessor :aad_authority

      # @return [String] Azure Active Directory tenant ID.
      attr_accessor :aad_tenant_id

      # @return [String] Azure Active Directory service principal client ID.
      attr_accessor :service_principal_client_id

      # @return [String] Azure Active Directory service principal object ID.
      attr_accessor :service_principal_object_id

      # @return [String] The azure management endpoint audience.
      attr_accessor :azure_management_endpoint_audience


      #
      # Mapper for UploadCertificateResponse class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'UploadCertificateResponse',
          type: {
            name: 'Composite',
            class_name: 'UploadCertificateResponse',
            model_properties: {
              auth_type: {
                client_side_validation: true,
                required: false,
                serialized_name: 'authType',
                type: {
                  name: 'String'
                }
              },
              resource_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'resourceId',
                type: {
                  name: 'String'
                }
              },
              aad_authority: {
                client_side_validation: true,
                required: true,
                serialized_name: 'aadAuthority',
                type: {
                  name: 'String'
                }
              },
              aad_tenant_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'aadTenantId',
                type: {
                  name: 'String'
                }
              },
              service_principal_client_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'servicePrincipalClientId',
                type: {
                  name: 'String'
                }
              },
              service_principal_object_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'servicePrincipalObjectId',
                type: {
                  name: 'String'
                }
              },
              azure_management_endpoint_audience: {
                client_side_validation: true,
                required: true,
                serialized_name: 'azureManagementEndpointAudience',
                type: {
                  name: 'String'
                }
              }
            }
          }
        }
      end
    end
  end
end
