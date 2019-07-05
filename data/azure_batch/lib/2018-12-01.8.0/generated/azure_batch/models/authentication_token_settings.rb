# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # The settings for an authentication token that the task can use to perform
    # Batch service operations.
    #
    #
    class AuthenticationTokenSettings

      include MsRestAzure

      # @return [Array<AccessScope>] The Batch resources to which the token
      # grants access. The authentication token grants access to a limited set
      # of Batch service operations. Currently the only supported value for the
      # access property is 'job', which grants access to all operations related
      # to the job which contains the task.
      attr_accessor :access


      #
      # Mapper for AuthenticationTokenSettings class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'AuthenticationTokenSettings',
          type: {
            name: 'Composite',
            class_name: 'AuthenticationTokenSettings',
            model_properties: {
              access: {
                client_side_validation: true,
                required: false,
                serialized_name: 'access',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'AccessScopeElementType',
                      type: {
                        name: 'Enum',
                        module: 'AccessScope'
                      }
                  }
                }
              }
            }
          }
        }
      end
    end
  end
end
