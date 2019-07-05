# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # The definition of the user identity under which the task is run.

    # Specify either the userName or autoUser property, but not both. On
    # CloudServiceConfiguration pools, this user is logged in with the
    # INTERACTIVE flag. On Windows VirtualMachineConfiguration pools, this user
    # is logged in with the BATCH flag.
    #
    class UserIdentity

      include MsRestAzure

      # @return [String] The name of the user identity under which the task is
      # run. The userName and autoUser properties are mutually exclusive; you
      # must specify one but not both.
      attr_accessor :user_name

      # @return [AutoUserSpecification] The auto user under which the task is
      # run. The userName and autoUser properties are mutually exclusive; you
      # must specify one but not both.
      attr_accessor :auto_user


      #
      # Mapper for UserIdentity class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'UserIdentity',
          type: {
            name: 'Composite',
            class_name: 'UserIdentity',
            model_properties: {
              user_name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'username',
                type: {
                  name: 'String'
                }
              },
              auto_user: {
                client_side_validation: true,
                required: false,
                serialized_name: 'autoUser',
                type: {
                  name: 'Composite',
                  class_name: 'AutoUserSpecification'
                }
              }
            }
          }
        }
      end
    end
  end
end
